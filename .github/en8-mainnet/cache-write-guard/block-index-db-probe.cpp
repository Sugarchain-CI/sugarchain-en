// Synthetic LevelDB storage diagnostic. No node or proof evidence is created.
#include <leveldb/cache.h>
#include <leveldb/db.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <leveldb/write_batch.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdarg>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#include <time.h>
#endif

namespace {
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
constexpr uint64_t MIB{1U << 20};
constexpr uint64_t BATCH_HEADERS{32'768};
constexpr size_t KEY_BYTES{33};
constexpr size_t INDEX_VALUE_BYTES{90};
constexpr size_t EVIDENCE_SHAPED_BYTES{33};

uint64_t Parse(std::string_view value)
{
    uint64_t result{};
    const auto [end, error]{std::from_chars(value.data(), value.data() + value.size(), result)};
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::runtime_error("Invalid numeric argument");
    }
    return result;
}

void Check(leveldb::Status status)
{
    if (!status.ok()) throw std::runtime_error(status.ToString());
}

uint64_t CpuNanoseconds()
{
#ifdef _WIN32
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) {
        throw std::runtime_error("GetProcessTimes failed");
    }
    const auto ticks = [](FILETIME time) {
        return (uint64_t{time.dwHighDateTime} << 32) | time.dwLowDateTime;
    };
    return (ticks(kernel) + ticks(user)) * 100;
#else
    timespec time{};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time) != 0) {
        throw std::runtime_error("clock_gettime failed");
    }
    return static_cast<uint64_t>(time.tv_sec) * 1'000'000'000 + time.tv_nsec;
#endif
}

struct TimeSample {
    Clock::time_point wall{Clock::now()};
    uint64_t cpu{CpuNanoseconds()};
};

struct Timing {
    double wall;
    uint64_t cpu_ns;
};

Timing Since(const TimeSample& start)
{
    const TimeSample now;
    if (now.cpu < start.cpu) throw std::runtime_error("Process CPU time regressed");
    return {std::chrono::duration<double>{now.wall - start.wall}.count(), now.cpu - start.cpu};
}

uint64_t PeakRssBytes()
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters{};
    if (!GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) {
        throw std::runtime_error("GetProcessMemoryInfo failed");
    }
    return counters.PeakWorkingSetSize;
#else
    struct rusage stats{};
    if (getrusage(RUSAGE_SELF, &stats) != 0) throw std::runtime_error("getrusage failed");
#ifdef __APPLE__
    return stats.ru_maxrss;
#else
    return static_cast<uint64_t>(stats.ru_maxrss) * 1024;
#endif
#endif
}

// SplitMix64 finalizer. Its bijection and the encoded entry ID produce unique
// keys with pseudo-random ordering and inexpensive exact value reconstruction.
uint64_t Mix(uint64_t n)
{
    n = (n ^ (n >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    n = (n ^ (n >> 27)) * UINT64_C(0x94d049bb133111eb);
    return n ^ (n >> 31);
}

void PutLE64(std::string& dest, size_t offset, uint64_t n)
{
    for (size_t i = 0; i < 8; ++i) dest[offset + i] = static_cast<char>((n >> (i * 8)) & 0xff);
}

uint64_t GetLE64(const char* data)
{
    uint64_t result{};
    for (size_t i = 0; i < 8; ++i) result |= uint64_t{static_cast<unsigned char>(data[i])} << (i * 8);
    return result;
}

std::string Key(uint64_t id, char type)
{
    std::string key(KEY_BYTES, type);
    PutLE64(key, 1, Mix(id));
    PutLE64(key, 9, Mix(id + 0x4d78f2a1ULL));
    PutLE64(key, 17, Mix(id + 0xdf7e0c4aULL));
    PutLE64(key, 25, id);
    return key;
}

std::string Value(uint64_t id, char type, bool rewritten)
{
    if (type == 'y') {
        // Version zero is deliberately invalid as proof evidence. These
        // synthetic values live only in a standalone benchmark database.
        std::string value(EVIDENCE_SHAPED_BYTES, '\0');
        for (size_t i = 0; i < 4; ++i) PutLE64(value, 1 + i * 8, Mix(id + 0x100 + i));
        return value;
    }

    std::string value(INDEX_VALUE_BYTES + (rewritten ? 12 : 0), '\0');
    const auto parent{Key(id == 0 ? 0 : id - 1, 'b')};
    value.replace(0, 32, parent, 1, 32);
    for (size_t i = 0; i < 4; ++i) PutLE64(value, 32 + i * 8, Mix(id + 0x300 + i));
    PutLE64(value, 64, id);
    PutLE64(value, 72, id * 5 + 0x5d553080ULL);
    PutLE64(value, 80, Mix(id + 0xc700));
    value[88] = rewritten ? char{0x1d} : char{0x02};
    if (rewritten) {
        PutLE64(value, INDEX_VALUE_BYTES, Mix(id + 0x501));
        value[INDEX_VALUE_BYTES + 8] = static_cast<char>(id & 0xff);
    }
    return value;
}

void AddFingerprint(uint64_t& fingerprint, std::string_view data)
{
    for (unsigned char byte : data) {
        fingerprint = (fingerprint ^ byte) * UINT64_C(1099511628211);
    }
}

struct WaitLog final : leveldb::Logger {
    std::atomic<uint64_t> full_memtable_waits{0};
    std::atomic<uint64_t> level_zero_waits{0};
    std::atomic<bool> compaction_error{false};

    void Logv(const char* format, std::va_list) override
    {
        const std::string_view text{format};
        if (text.find("Current memtable full; waiting") != std::string_view::npos) ++full_memtable_waits;
        if (text.find("Too many L0 files; waiting") != std::string_view::npos) ++level_zero_waits;
        if (text.find("Compaction error:") != std::string_view::npos) compaction_error = true;
    }
};

void SaveProperty(leveldb::DB& db, const fs::path& output, const char* name)
{
    std::string value;
    if (!db.GetProperty(name, &value)) throw std::runtime_error(std::string{"Missing DB property: "} + name);
    std::ofstream stream(output, std::ios::binary);
    if (!(stream << value)) throw std::runtime_error("Cannot save DB property");
}

uint64_t DirectoryBytes(const fs::path& directory)
{
    uint64_t total{0};
    for (const auto& item : fs::recursive_directory_iterator(directory)) {
        if (item.is_regular_file()) total += item.file_size();
    }
    return total;
}

double Quantile(std::vector<double> values, size_t percent)
{
    std::sort(values.begin(), values.end());
    const size_t index{(values.size() * percent + 99) / 100 - 1};
    return values[index];
}

struct Phase {
    Timing elapsed{};
    std::vector<double> sync_wall;
    uint64_t full_memtable_waits{};
    uint64_t level_zero_waits{};
};

Phase WriteRows(leveldb::DB& db, const WaitLog& logger, std::ostream& batches,
                uint64_t rows, bool rewrite)
{
    Phase result;
    const uint64_t initial_memtable{logger.full_memtable_waits.load()};
    const uint64_t initial_l0{logger.level_zero_waits.load()};
    const TimeSample begin;
    leveldb::WriteOptions options;
    options.sync = true;
    for (uint64_t start = 0; start < rows; start += BATCH_HEADERS) {
        leveldb::WriteBatch batch;
        const uint64_t end{std::min(rows, start + BATCH_HEADERS)};
        for (uint64_t id = start; id < end; ++id) {
            batch.Put(Key(id, 'b'), Value(id, 'b', rewrite));
            if (!rewrite) batch.Put(Key(id, 'y'), Value(id, 'y', false));
        }
        const TimeSample write_start;
        Check(db.Write(options, &batch));
        const Timing write{Since(write_start)};
        result.sync_wall.push_back(write.wall);
        batches << (rewrite ? "status_rewrite" : "ingest") << '\t' << start << '\t' << end - start
                << '\t' << batch.ApproximateSize() << '\t' << write.wall << '\t' << write.cpu_ns << '\n';
    }
    result.elapsed = Since(begin);
    result.full_memtable_waits = logger.full_memtable_waits.load() - initial_memtable;
    result.level_zero_waits = logger.level_zero_waits.load() - initial_l0;
    return result;
}

void WriteTiming(std::ostream& output, const char* name, const Timing& timing)
{
    output << "  \"" << name << "_wall_seconds\": " << timing.wall << ",\n"
           << "  \"" << name << "_cpu_ns\": " << timing.cpu_ns << ",\n";
}

void WritePhase(std::ostream& output, const char* name, const Phase& phase)
{
    WriteTiming(output, name, phase.elapsed);
    output << "  \"" << name << "_sync_writes\": " << phase.sync_wall.size() << ",\n"
           << "  \"" << name << "_sync_p95_seconds\": " << Quantile(phase.sync_wall, 95) << ",\n"
           << "  \"" << name << "_memtable_waits\": " << phase.full_memtable_waits << ",\n"
           << "  \"" << name << "_level_zero_waits\": " << phase.level_zero_waits << ",\n";
}

void CheckNative()
{
#ifdef _WIN32
    USHORT process{}, host{};
    if (!IsWow64Process2(GetCurrentProcess(), &process, &host) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || host != IMAGE_FILE_MACHINE_AMD64 || sizeof(void*) != 8) {
        throw std::runtime_error("Native Windows AMD64 is required");
    }
#endif
}
} // namespace

int main(int argc, char** argv)
{
    try {
        CheckNative();
        if (argc != 4) throw std::runtime_error("Usage: block-index-db-probe NEW_OUTPUT MAX_OPEN_FILES ROWS");
        const fs::path output{argv[1]};
        const auto max_open_files{Parse(argv[2])};
        const auto rows{Parse(argv[3])};
        if ((max_open_files != 1000 && max_open_files != 10 && max_open_files != 42) ||
            rows == 0 || rows > 1'048'576) {
            throw std::runtime_error("Use 1000, 10 or 42 max_open_files and 1–1,048,576 rows");
        }
        if (!fs::create_directory(output)) throw std::runtime_error("An unused output directory is required");
        const auto db_path{output / "synthetic-index"};
        const auto utf8{db_path.u8string()};
        const std::string name(utf8.begin(), utf8.end());

        constexpr size_t CACHE_BYTES{64 * MIB};
        std::unique_ptr<leveldb::Cache> cache{leveldb::NewLRUCache(CACHE_BYTES / 2)};
        std::unique_ptr<const leveldb::FilterPolicy> bloom{leveldb::NewBloomFilterPolicy(10)};
        WaitLog logger;
        leveldb::Options options;
        options.create_if_missing = true;
        options.error_if_exists = true;
        options.paranoid_checks = true;
        options.block_cache = cache.get();
        options.write_buffer_size = CACHE_BYTES / 4;
        options.filter_policy = bloom.get();
        options.compression = leveldb::kNoCompression;
        options.max_file_size = std::max<size_t>(options.max_file_size, 32 * MIB);
        options.info_log = &logger;
        options.max_open_files = static_cast<int>(max_open_files);
        options.small_table_cache = max_open_files != 1000;

        leveldb::DB* handle{nullptr};
        Check(leveldb::DB::Open(options, name, &handle));
        std::unique_ptr<leveldb::DB> database{handle};
        std::ofstream batches(output / "sync-writes.tsv");
        batches << std::setprecision(9) << "phase\tstart_id\trows\tbatch_bytes\twall_seconds\tcpu_ns\n";
        const Phase ingest{WriteRows(*database, logger, batches, rows, false)};
        const TimeSample ingest_compact_begin;
        database->CompactRange(nullptr, nullptr);
        const Timing ingest_compact{Since(ingest_compact_begin)};
        SaveProperty(*database, output / "ingest-compaction.txt", "leveldb.stats");

        const Phase rewrite{WriteRows(*database, logger, batches, rows, true)};
        const TimeSample rewrite_compact_begin;
        database->CompactRange(nullptr, nullptr);
        const Timing rewrite_compact{Since(rewrite_compact_begin)};
        SaveProperty(*database, output / "rewrite-compaction.txt", "leveldb.stats");
        const uint64_t disk_bytes{DirectoryBytes(db_path)};
        const TimeSample close_begin;
        database.reset();
        const Timing close{Since(close_begin)};
        if (logger.compaction_error.load()) throw std::runtime_error("LevelDB reported a compaction error");
        const uint64_t peak_write{PeakRssBytes()};
        batches.close();
        if (!batches) throw std::runtime_error("Cannot save sync write times");

        // Reopen with a new block cache. The OS file cache is left in its
        // natural post-write state for every arm.
        cache.reset(leveldb::NewLRUCache(CACHE_BYTES / 2));
        options.block_cache = cache.get();
        options.create_if_missing = false;
        options.error_if_exists = false;
        const TimeSample reopen_begin;
        Check(leveldb::DB::Open(options, name, &handle));
        database.reset(handle);
        const Timing reopen{Since(reopen_begin)};
        leveldb::ReadOptions read_options;
        read_options.verify_checksums = true;
        read_options.fill_cache = false;
        const TimeSample validate_begin;
        auto iterator{std::unique_ptr<leveldb::Iterator>{database->NewIterator(read_options)}};
        uint64_t verified_index{}, verified_evidence{};
        uint64_t fingerprint{UINT64_C(14695981039346656037)};
        for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
            const auto key{iterator->key()};
            const auto value{iterator->value()};
            if (key.size() != KEY_BYTES) throw std::runtime_error("Invalid key length");
            const char type{key.data()[0]};
            const auto id{GetLE64(key.data() + 25)};
            if ((type != 'b' && type != 'y') || id >= rows ||
                key.ToString() != Key(id, type) || value.ToString() != Value(id, type, true)) {
                throw std::runtime_error("Stored key or value mismatch after reopen");
            }
            AddFingerprint(fingerprint, {key.data(), key.size()});
            AddFingerprint(fingerprint, {value.data(), value.size()});
            if (type == 'b') ++verified_index;
            else ++verified_evidence;
        }
        Check(iterator->status());
        if (verified_index != rows || verified_evidence != rows) {
            throw std::runtime_error("Missing or extra records after reopen");
        }
        iterator.reset();
        const Timing validate{Since(validate_begin)};

        const TimeSample sentinel_begin;
        uint64_t sentinels{};
        for (const uint64_t id : {uint64_t{0}, std::min(rows - 1, BATCH_HEADERS - 1),
                                  std::min(rows - 1, BATCH_HEADERS), rows / 3, rows - 1}) {
            for (const char type : {'b', 'y'}) {
                std::string actual;
                Check(database->Get(read_options, Key(id, type), &actual));
                if (actual != Value(id, type, true)) throw std::runtime_error("Sentinel mismatch after reopen");
                ++sentinels;
            }
        }
        const Timing sentinel{Since(sentinel_begin)};
        database.reset();

        std::ofstream result(output / "result.json");
        result << std::setprecision(9)
               << "{\n  \"status\": \"verified\",\n"
               << "  \"workload\": \"synthetic index-shaped LevelDB status rewrites\",\n"
               << "  \"max_open_files\": " << max_open_files << ",\n"
               << "  \"small_table_cache\": " << std::boolalpha << options.small_table_cache << ",\n"
               << "  \"table_cache_nominal_entries\": " << max_open_files - 10 << ",\n"
               << "  \"cache_mib\": 64,\n"
               << "  \"block_cache_bytes\": " << CACHE_BYTES / 2 << ",\n"
               << "  \"write_buffer_bytes\": " << options.write_buffer_size << ",\n"
               << "  \"max_file_size_bytes\": " << options.max_file_size << ",\n"
               << "  \"rows\": " << rows << ",\n"
               << "  \"verified_index\": " << verified_index << ",\n"
               << "  \"verified_evidence\": " << verified_evidence << ",\n"
               << "  \"verified_sentinels\": " << sentinels << ",\n"
               << "  \"ordered_fnv1a64\": \"" << std::hex << std::setw(16) << std::setfill('0')
               << fingerprint << std::dec << "\",\n";
        WritePhase(result, "ingest", ingest);
        WriteTiming(result, "ingest_compaction", ingest_compact);
        WritePhase(result, "status_rewrite", rewrite);
        WriteTiming(result, "rewrite_compaction", rewrite_compact);
        WriteTiming(result, "close", close);
        WriteTiming(result, "reopen", reopen);
        WriteTiming(result, "verify_scan", validate);
        WriteTiming(result, "sentinels", sentinel);
        result << "  \"peak_write_rss_bytes\": " << peak_write << ",\n"
               << "  \"peak_rss_bytes\": " << PeakRssBytes() << ",\n"
               << "  \"disk_bytes_after_compaction\": " << disk_bytes << "\n}\n";
        result.close();
        if (!result) throw std::runtime_error("Cannot save result");
        std::cout << "Verified " << verified_index + verified_evidence << " records, open-file limit "
                  << max_open_files << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
