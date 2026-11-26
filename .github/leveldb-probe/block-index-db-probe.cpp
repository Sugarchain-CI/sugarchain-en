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

double Elapsed(Clock::time_point from)
{
    return std::chrono::duration<double>{Clock::now() - from}.count();
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

std::string Value(uint64_t id, char type)
{
    if (type == 'y') {
        // Version zero is deliberately invalid as proof evidence. These
        // synthetic values live only in a standalone benchmark database.
        std::string value(EVIDENCE_SHAPED_BYTES, '\0');
        for (size_t i = 0; i < 4; ++i) PutLE64(value, 1 + i * 8, Mix(id + 0x100 + i));
        return value;
    }

    std::string value(INDEX_VALUE_BYTES, '\0');
    const auto parent{Key(id == 0 ? 0 : id - 1, 'b')};
    value.replace(0, 32, parent, 1, 32);
    for (size_t i = 0; i < 4; ++i) PutLE64(value, 32 + i * 8, Mix(id + 0x300 + i));
    PutLE64(value, 64, id);
    PutLE64(value, 72, id * 5 + 0x5d553080ULL);
    PutLE64(value, 80, Mix(id + 0xc700));
    return value;
}

struct WaitLog final : leveldb::Logger {
    std::atomic<uint64_t> full_memtable_waits{0};
    std::atomic<uint64_t> level_zero_waits{0};

    void Logv(const char* format, std::va_list) override
    {
        const std::string_view text{format};
        if (text.find("Current memtable full; waiting") != std::string_view::npos) ++full_memtable_waits;
        if (text.find("Too many L0 files; waiting") != std::string_view::npos) ++level_zero_waits;
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
} // namespace

int main(int argc, char** argv)
{
    try {
        if (argc != 4) throw std::runtime_error("Usage: block-index-db-probe NEW_OUTPUT CACHE_MIB HEADER_COUNT");
        const fs::path output{argv[1]};
        const auto cache_mib{Parse(argv[2])};
        const auto headers{Parse(argv[3])};
        if ((cache_mib != 2 && cache_mib != 16 && cache_mib != 64) || headers == 0 || headers > 8'388'608) {
            throw std::runtime_error("Use 2, 16 or 64 MiB and 1–8,388,608 headers");
        }
        if (!fs::create_directory(output)) throw std::runtime_error("An unused output directory is required");
        const auto path{(output / "synthetic-index").u8string()};
        const std::string name(path.begin(), path.end());

        // Match current GetOptions plus constructor defaults for 64-bit
        // production databases. Actual CDBWrapper is not linked.
        const size_t cache_bytes{static_cast<size_t>(cache_mib * MIB)};
        std::unique_ptr<leveldb::Cache> cache{leveldb::NewLRUCache(cache_bytes / 2)};
        std::unique_ptr<const leveldb::FilterPolicy> bloom{leveldb::NewBloomFilterPolicy(10)};
        WaitLog logger;
        leveldb::Options options;
        options.create_if_missing = true;
        options.error_if_exists = true;
        options.paranoid_checks = true;
        options.block_cache = cache.get();
        options.write_buffer_size = cache_bytes / 4;
        options.filter_policy = bloom.get();
        options.compression = leveldb::kNoCompression;
        options.max_file_size = std::max<size_t>(options.max_file_size, 32 * MIB);
        options.info_log = &logger;

        leveldb::DB* handle{nullptr};
        Check(leveldb::DB::Open(options, name, &handle));
        std::unique_ptr<leveldb::DB> database{handle};
        leveldb::WriteOptions write_options;
        write_options.sync = true;
        std::vector<double> latencies;
        std::vector<size_t> batch_bytes;
        double write_total{0};
        const auto ingest_start{Clock::now()};
        for (uint64_t start = 0; start < headers; start += BATCH_HEADERS) {
            leveldb::WriteBatch batch;
            const uint64_t end{std::min(headers, start + BATCH_HEADERS)};
            for (uint64_t id = start; id < end; ++id) {
                for (const char type : {'b', 'y'}) batch.Put(Key(id, type), Value(id, type));
            }
            batch_bytes.push_back(batch.ApproximateSize());
            const auto write_start{Clock::now()};
            Check(database->Write(write_options, &batch));
            latencies.push_back(Elapsed(write_start));
            write_total += latencies.back();
        }
        const double ingest{Elapsed(ingest_start)};
        const uint64_t peak_write{PeakRssBytes()};
        const uint64_t ingest_full_waits{logger.full_memtable_waits.load()};
        const uint64_t ingest_l0_waits{logger.level_zero_waits.load()};
        SaveProperty(*database, output / "compaction-before.txt", "leveldb.stats");
        SaveProperty(*database, output / "memory-before.txt", "leveldb.approximate-memory-usage");

        // Timed separately so a cache cannot look fast merely by deferring
        // compaction. This is explicitly forced work, not normal node timing.
        const auto drain_start{Clock::now()};
        database->CompactRange(nullptr, nullptr);
        const double drain{Elapsed(drain_start)};
        SaveProperty(*database, output / "compaction-after.txt", "leveldb.stats");
        const uint64_t disk_bytes{DirectoryBytes(output / "synthetic-index")};
        database.reset();

        options.create_if_missing = false;
        options.error_if_exists = false;
        const auto reopen_start{Clock::now()};
        Check(leveldb::DB::Open(options, name, &handle));
        database.reset(handle);
        const double reopen{Elapsed(reopen_start)};
        leveldb::ReadOptions read_options;
        read_options.verify_checksums = true;
        read_options.fill_cache = false;
        std::unique_ptr<leveldb::Iterator> iterator{database->NewIterator(read_options)};
        const auto verify_start{Clock::now()};
        uint64_t checked{0};
        for (iterator->SeekToFirst(); iterator->Valid(); iterator->Next()) {
            const auto key{iterator->key()};
            if (key.size() != KEY_BYTES) throw std::runtime_error("Invalid key length");
            const char type{key.data()[0]};
            const auto id{GetLE64(key.data() + 25)};
            if ((type != 'b' && type != 'y') || id >= headers ||
                key.ToString() != Key(id, type) || iterator->value().ToString() != Value(id, type)) {
                throw std::runtime_error("Stored key or value mismatch after reopen");
            }
            ++checked;
        }
        Check(iterator->status());
        if (checked != headers * 2) throw std::runtime_error("Missing or extra records after reopen");
        const double verify{Elapsed(verify_start)};
        const uint64_t peak_total{PeakRssBytes()};

        std::ofstream rows(output / "sync-writes.tsv");
        rows << "batch\tbytes\tseconds\n";
        for (size_t i = 0; i < latencies.size(); ++i) {
            rows << i + 1 << '\t' << batch_bytes[i] << '\t' << std::setprecision(9) << latencies[i] << '\n';
        }
        if (!rows) throw std::runtime_error("Cannot save sync write times");

        std::ofstream result(output / "result.json");
        result << std::setprecision(9)
               << "{\n  \"status\": \"verified\",\n"
               << "  \"workload\": \"synthetic index-shaped LevelDB storage\",\n"
               << "  \"cache_mib\": " << cache_mib << ",\n"
               << "  \"block_cache_bytes\": " << cache_bytes / 2 << ",\n"
               << "  \"write_buffer_bytes\": " << options.write_buffer_size << ",\n"
               << "  \"headers\": " << headers << ",\n"
               << "  \"verified_records\": " << checked << ",\n"
               << "  \"sync_writes\": " << latencies.size() << ",\n"
               << "  \"ingest_seconds\": " << ingest << ",\n"
               << "  \"sync_write_seconds_sum\": " << write_total << ",\n"
               << "  \"sync_write_p50_seconds\": " << Quantile(latencies, 50) << ",\n"
               << "  \"sync_write_p95_seconds\": " << Quantile(latencies, 95) << ",\n"
               << "  \"peak_ingest_rss_bytes\": " << peak_write << ",\n"
               << "  \"peak_total_rss_bytes\": " << peak_total << ",\n"
               << "  \"full_memtable_wait_log_count\": " << ingest_full_waits << ",\n"
               << "  \"level_zero_wait_log_count\": " << ingest_l0_waits << ",\n"
               << "  \"forced_compaction_seconds\": " << drain << ",\n"
               << "  \"disk_bytes_after_compaction\": " << disk_bytes << ",\n"
               << "  \"reopen_seconds\": " << reopen << ",\n"
               << "  \"verify_seconds\": " << verify << "\n}\n";
        if (!result) throw std::runtime_error("Cannot save result");
        std::cout << "Verified " << checked << " records after reopen; " << cache_mib
                  << " MiB in " << ingest << " s ingest.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
