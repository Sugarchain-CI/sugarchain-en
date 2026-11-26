// Diagnostic only. The include overlay injects these observations into the
// actual source-9c pool allocation and chunk allocation paths.
#include <cstddef>

namespace report {
void Allocate(std::size_t bytes, std::size_t alignment, bool pooled);
void Chunk(std::size_t bytes);
}

#include <node/blockmap.h>

#include <array>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <stdexcept>
#include <tuple>

#ifdef __APPLE__
#include <cstring>
#include <sys/mount.h>
#else
#include <sys/statvfs.h>
#endif

namespace {
constexpr std::size_t SAMPLE{8192};
constexpr std::uint64_t CHECKPOINT_ROWS{44'946'269};
constexpr std::uint64_t FIXTURE_BYTES{10'188'893'398};
constexpr std::uint64_t LARGEST_PART_BYTES{1ULL << 30};
constexpr std::uint64_t RESERVE_BYTES{8ULL << 30};
constexpr std::uint64_t CHUNK_BYTES{1ULL << 18};

using Allocation = std::tuple<std::size_t, std::size_t, bool>;
struct Phase {
    std::map<Allocation, std::size_t> allocations;
    std::map<std::size_t, std::size_t> chunks;
};

Phase* active_phase{};

std::uint64_t CeilingDiv(std::uint64_t numerator, std::uint64_t denominator)
{
    return numerator / denominator + (numerator % denominator != 0);
}

uint256 Key(std::size_t i)
{
    uint256 key;
    WriteLE64(key.begin(), static_cast<std::uint64_t>(i + 1));
    return key;
}

void PrintPhase(const char* label, const Phase& phase)
{
    std::cout << "  \"" << label << "\": {\"allocations\": [";
    const char* sep{""};
    for (const auto& [shape, count] : phase.allocations) {
        const auto [bytes, alignment, pooled]{shape};
        std::cout << sep << "{\"bytes\": " << bytes << ", \"alignment\": " << alignment
                  << ", \"pooled\": " << pooled << ", \"count\": " << count << '}';
        sep = ", ";
    }
    std::cout << "], \"chunks\": [";
    sep = "";
    for (const auto& [bytes, count] : phase.chunks) {
        std::cout << sep << "{\"bytes\": " << bytes << ", \"count\": " << count << '}';
        sep = ", ";
    }
    std::cout << "]},\n";
}

struct DiskGeometry {
    std::uint64_t available;
    bool local_apfs;
};

DiskGeometry Disk(const char* path)
{
#ifdef __APPLE__
    struct statfs status{};
    if (statfs(path, &status) != 0 || status.f_bsize <= 0) throw std::runtime_error("statfs failed");
    return {static_cast<std::uint64_t>(status.f_bavail) * status.f_bsize,
            (status.f_flags & MNT_LOCAL) != 0 && std::strcmp(status.f_fstypename, "apfs") == 0};
#else
    struct statvfs status{};
    if (statvfs(path, &status) != 0 || status.f_frsize == 0) throw std::runtime_error("statvfs failed");
    return {static_cast<std::uint64_t>(status.f_bavail) * status.f_frsize, false};
#endif
}
} // namespace

namespace report {
void Allocate(std::size_t bytes, std::size_t alignment, bool pooled)
{
    if (active_phase) ++active_phase->allocations[{bytes, alignment, pooled}];
}

void Chunk(std::size_t bytes)
{
    if (active_phase) ++active_phase->chunks[bytes];
}
} // namespace report

int main(int argc, char** argv)
{
    try {
        if (argc != 2 || !std::filesystem::path{argv[1]}.is_absolute()) {
            throw std::runtime_error("Usage: blockmap-geometry ABSOLUTE_SCRATCH_DIR");
        }
        const DiskGeometry disk{Disk(argv[1])};
        Phase constructor, reserve, insert;
        std::array<CBlockIndex*, SAMPLE> pointers{};
        active_phase = &constructor;
        node::BlockMap map{true};
        active_phase = &reserve;
        map.reserve(SAMPLE + SAMPLE / 2);
        const std::size_t buckets{map.bucket_count()};
        active_phase = &insert;
        for (std::size_t i = 0; i < SAMPLE; ++i) {
            const auto [position, inserted]{map.try_emplace(Key(i))};
            if (!inserted) throw std::runtime_error("Duplicate sample key");
            position->second.phashBlock = &position->first;
            if (i > 0) position->second.pprev = pointers[i - 1];
            pointers[i] = &position->second;
        }
        active_phase = nullptr;
        for (std::size_t i = 0; i < SAMPLE; ++i) {
            const auto position{map.find(Key(i))};
            if (position == map.end() || &position->second != pointers[i] ||
                position->second.phashBlock != &position->first ||
                position->second.pprev != (i > 0 ? pointers[i - 1] : nullptr)) {
                throw std::runtime_error("Sample pointer validation failed");
            }
        }
        const bool layout{
            map.IsFast() && map.size() == SAMPLE && map.bucket_count() == buckets &&
            constructor.allocations.empty() && constructor.chunks == std::map<std::size_t, std::size_t>{{CHUNK_BYTES, 1}} &&
            reserve.allocations == std::map<Allocation, std::size_t>{{{buckets * sizeof(void*), alignof(void*), false}, 1}} &&
            reserve.chunks.empty() && insert.allocations.size() == 1};
        std::size_t raw_bytes{}, alignment{}, stride{}, nodes_per_chunk{};
        std::uint64_t required_chunks{}, arena_bytes{};
        bool verified{};
        if (layout) {
            const auto& [shape, measured_allocations]{*insert.allocations.begin()};
            const auto [bytes, align, pooled]{shape};
            raw_bytes = bytes;
            alignment = align;
            stride = (raw_bytes + 7) / 8 * 8;
            if (pooled && raw_bytes > 0 && raw_bytes <= 512 && alignment <= 8 && measured_allocations == SAMPLE) {
                nodes_per_chunk = CHUNK_BYTES / stride;
                required_chunks = CeilingDiv(CHECKPOINT_ROWS, nodes_per_chunk);
                arena_bytes = required_chunks * CHUNK_BYTES;
                const std::size_t sample_chunks{CeilingDiv(SAMPLE, nodes_per_chunk)};
                verified = insert.chunks == std::map<std::size_t, std::size_t>{{CHUNK_BYTES, sample_chunks - 1}};
                for (std::size_t i = 1; i < SAMPLE && verified; ++i) {
                    if (i % nodes_per_chunk == 0) continue;
                    const auto current{reinterpret_cast<std::uintptr_t>(pointers[i])};
                    const auto previous{reinterpret_cast<std::uintptr_t>(pointers[i - 1])};
                    verified = current >= previous && current - previous == stride;
                }
            }
        }
        const auto extraction_bytes{FIXTURE_BYTES + LARGEST_PART_BYTES + RESERVE_BYTES};
        const auto mature_bytes{FIXTURE_BYTES + arena_bytes + RESERVE_BYTES};
        std::cout << std::boolalpha << "{\n"
                  << "  \"status\": \"" << (verified ? "geometry_verified" : "unexpected_geometry") << "\",\n"
                  << "  \"sample_nodes\": " << SAMPLE << ",\n"
                  << "  \"key_bytes\": " << sizeof(uint256) << ",\n"
                  << "  \"index_bytes\": " << sizeof(CBlockIndex) << ",\n"
                  << "  \"value_bytes\": " << sizeof(node::FastBlockMap::value_type) << ",\n"
                  << "  \"buckets\": " << buckets << ",\n";
        PrintPhase("construction", constructor);
        PrintPhase("reserve", reserve);
        PrintPhase("insert", insert);
        std::cout << "  \"raw_node_allocation_bytes\": " << raw_bytes << ",\n"
                  << "  \"node_alignment_bytes\": " << alignment << ",\n"
                  << "  \"rounded_node_stride_bytes\": " << stride << ",\n"
                  << "  \"nodes_per_chunk\": " << nodes_per_chunk << ",\n"
                  << "  \"checkpoint_rows\": " << CHECKPOINT_ROWS << ",\n"
                  << "  \"arena_chunks\": " << required_chunks << ",\n"
                  << "  \"arena_bytes\": " << arena_bytes << ",\n"
                  << "  \"fixture_bytes\": " << FIXTURE_BYTES << ",\n"
                  << "  \"largest_part_bytes\": " << LARGEST_PART_BYTES << ",\n"
                  << "  \"reserve_bytes\": " << RESERVE_BYTES << ",\n"
                  << "  \"available_disk_bytes\": " << disk.available << ",\n"
                  << "  \"local_apfs\": " << disk.local_apfs << ",\n"
                  << "  \"required_stream_extract_bytes\": " << extraction_bytes << ",\n"
                  << "  \"required_fixture_arena_and_reserve_bytes\": " << mature_bytes << ",\n"
                  << "  \"fits_observed_disk_preflight\": " << (verified && disk.local_apfs && disk.available >= std::max(extraction_bytes, mature_bytes))
                  << "\n}\n";
        return verified ? 0 : 2;
    } catch (const std::exception& error) {
        active_phase = nullptr;
        std::cerr << error.what() << '\n';
        return 1;
    }
}
