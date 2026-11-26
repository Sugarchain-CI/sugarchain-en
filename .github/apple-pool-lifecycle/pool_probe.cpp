#include "mapped_pool_arena.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {
constexpr size_t CHUNK_BYTES{256 << 10};
constexpr size_t MAX_NODES{size_t{2} << 20};
constexpr size_t MAX_PRESSURE_MIB{1024};
using Key = std::array<uint64_t, 4>;
using Clock = std::chrono::steady_clock;

void Require(bool ok, const char* reason)
{
    if (!ok) throw std::runtime_error{reason};
}

size_t Number(std::string_view input)
{
    size_t value{0};
    const auto parsed{std::from_chars(input.data(), input.data() + input.size(), value)};
    Require(parsed.ec == std::errc{} && parsed.ptr == input.data() + input.size(), "invalid number");
    return value;
}

uint64_t Mix(uint64_t n)
{
    n ^= n >> 30;
    n *= 0xbf58476d1ce4e5b9ULL;
    n ^= n >> 27;
    n *= 0x94d049bb133111ebULL;
    return n ^ (n >> 31);
}

Key IndexKey(size_t id)
{
    return {Mix(id), Mix(id + MAX_NODES), Mix(id + 2 * MAX_NODES), Mix(id + 3 * MAX_NODES)};
}

struct ProbeNode
{
    uint64_t height{0};
    const Key* key{nullptr};
    const ProbeNode* parent{nullptr};
    std::array<uint64_t, 16> words{};
    inline static size_t destructions{0};
    ~ProbeNode() { ++destructions; }
};
static_assert(sizeof(ProbeNode) == 152);
static_assert(sizeof(std::pair<const Key, ProbeNode>) == 184);

struct FastHash {
    size_t operator()(const Key& key) const noexcept { return key.front(); }
};

using Allocator = PoolAllocator<std::pair<const Key, ProbeNode>, 512, 8>;
using ProbeMap = std::unordered_map<Key, ProbeNode, FastHash, std::equal_to<Key>, Allocator>;

double Elapsed(Clock::time_point start)
{
    return std::chrono::duration<double>(Clock::now() - start).count();
}

struct FreelistSlot {
    std::array<std::byte, 192> body;
};

void CheckFreelistFallback()
{
    ReservedChunkRange unavailable;
    {
        PoolResource<512, 8> pool{512, &unavailable};
        void* heap{pool.Allocate(192, 8)};
        Require(!unavailable.Owns(heap) && unavailable.ReturnedChunks() == 0, "unavailable arena fallback");
        pool.Deallocate(heap, 192, 8);
    }
    // Only the first whole slab fits. The second allocation is forced onto the
    // heap with a deterministic finite arena, while the first still lives.
    constexpr size_t SMALL_CHUNK{512};
    alignas(8) std::array<std::byte, SMALL_CHUNK + 8> scratch{};
    ReservedChunkRange range;
    range.SetUp(scratch);
    {
        PoolResource<512, 8> pool{SMALL_CHUNK, &range};
        PoolAllocator<FreelistSlot, 512, 8> allocator{&pool};
        auto* first{std::construct_at(allocator.allocate(1))};
        auto* second{std::construct_at(allocator.allocate(1))};
        auto* third{std::construct_at(allocator.allocate(1))};
        Require(range.Owns(first) && range.Owns(second) && !range.Owns(third), "mixed-owner fallback");
        Require(reinterpret_cast<std::uintptr_t>(third) % 8 == 0, "fallback alignment");
        first->body.fill(std::byte{0x11});
        third->body.fill(std::byte{0x22});
        std::destroy_at(second);
        allocator.deallocate(second, 1);
        auto* reused{std::construct_at(allocator.allocate(1))};
        Require(reused == second, "existing freelist reuse");
        Require(first->body.back() == std::byte{0x11} && third->body.back() == std::byte{0x22},
                "payload changed during fallthrough");
        for (auto* slot : {first, reused, third}) {
            std::destroy_at(slot);
            allocator.deallocate(slot, 1);
        }
    }
    Require(range.ReturnedChunks() == 1, "one whole arena slab");
}

int Run(std::string_view mode, size_t count, size_t pressure_mib, ReservedChunkRange* arena)
{
    ProbeNode::destructions = 0;
    std::vector<std::byte> pressure(pressure_mib << 20);
    for (size_t position = 0; position < pressure.size(); position += 4096) {
        pressure[position] = std::byte{0x4D};
    }
    std::vector<size_t> order(count);
    std::iota(order.begin(), order.end(), size_t{0});
    std::mt19937_64 sequence{0xC00253A31ULL};
    std::shuffle(order.begin(), order.end(), sequence);
    std::vector<const ProbeNode*> height_pointers(count);
    PoolResource<512, 8> pool{CHUNK_BYTES, arena};
    auto table = std::make_unique<ProbeMap>(0, FastHash{}, std::equal_to<Key>{}, Allocator{&pool});
    table->reserve(count + count / 2);

    auto start{Clock::now()};
    for (const size_t height : order) {
        const auto item{table->try_emplace(IndexKey(height)).first};
        auto& value{item->second};
        value.height = height;
        value.key = &item->first;
        value.parent = height ? &table->try_emplace(IndexKey(height - 1)).first->second : nullptr;
        for (size_t i = 0; i < value.words.size(); ++i) value.words[i] = Mix(height + i * count);
        height_pointers[height] = &value;
    }
    const double ingest{Elapsed(start)};
    Require(table->size() == count, "unexpected index count");

    // Verify pointer and byte identity after a rehash, then scan the captured
    // nodes in height order. Rehash is a separate correctness control.
    table->rehash(table->bucket_count() + count / 2 + 1);
    start = Clock::now();
    for (const size_t height : order) {
        const auto item{table->find(IndexKey(height))};
        Require(item != table->end() && &item->second == height_pointers[height] &&
                item->second.key == &item->first, "key and value pointer stability");
    }
    const double lookups{Elapsed(start)};

    start = Clock::now();
    uint64_t checksum{0};
    for (size_t height = 0; height < count; ++height) {
        const auto& value{*height_pointers[height]};
        const auto* parent{height ? height_pointers[height - 1] : nullptr};
        Require(value.height == height && value.parent == parent && *value.key == IndexKey(height),
                "height or ancestry identity");
        for (size_t i = 0; i < value.words.size(); ++i) {
            Require(value.words[i] == Mix(height + i * count), "node byte identity");
            checksum = Mix(checksum ^ value.words[i]);
        }
    }
    const double height_reads{Elapsed(start)};

    const size_t chunks{pool.NumAllocatedChunks()};
    const size_t arena_chunks{arena ? arena->ReturnedChunks() : 0};
    Require(chunks >= arena_chunks, "source ownership count");
    if (mode == "mixed") Require(arena_chunks == 2 && chunks > arena_chunks, "expected mixed chunk sources");
    start = Clock::now();
    table.reset();
    const double destruct{Elapsed(start)};
    Require(ProbeNode::destructions == count, "node destructor count");
    for (size_t position = 0; position < pressure.size(); position += 4096) {
        Require(pressure[position] == std::byte{0x4D}, "pressure byte identity");
    }
    std::cout << std::fixed << std::setprecision(6)
              << "{\"status\":\"verified\",\"mode\":\"" << mode
              << "\",\"nodes\":" << count << ",\"pressure_mib\":" << pressure_mib
              << ",\"total_pool_chunks\":" << chunks << ",\"arena_chunks\":" << arena_chunks
              << ",\"anonymous_chunks\":" << chunks - arena_chunks
              << ",\"all_pool_chunks_file_backed\":" << (mode == "file" && chunks == arena_chunks ? "true" : "false")
              << ",\"checksum\":\"" << std::hex << checksum
              << std::dec << "\",\"ingest_seconds\":" << ingest << ",\"lookup_seconds\":" << lookups
              << ",\"height_scan_seconds\":" << height_reads << ",\"destruct_seconds\":" << destruct << "}\n";
    return 0;
}
} // namespace

int main(int argc, char** argv)
{
    try {
        Require(argc == 4 || argc == 6, "usage: pool_probe heap|mixed|file NODES PRESSURE_MIB [ABS_SCRATCH ARENA_BYTES]");
        const std::string_view mode{argv[1]};
        const size_t count{Number(argv[2])};
        const size_t pressure_mib{Number(argv[3])};
        Require(count >= 8192 && count <= MAX_NODES && pressure_mib <= MAX_PRESSURE_MIB, "outside probe bounds");
        CheckFreelistFallback();
        if (mode == "heap") {
            Require(argc == 4, "heap takes no file arguments");
            return Run(mode, count, pressure_mib, nullptr);
        }
        if (mode == "mixed") {
            Require(argc == 4, "mixed takes no file arguments");
            std::vector<std::byte> memory(2 * CHUNK_BYTES);
            ReservedChunkRange arena;
            arena.SetUp(memory);
            return Run(mode, count, pressure_mib, &arena);
        }
        Require(mode == "file" && argc == 6, "file requires an absolute scratch and arena size");
#if defined(__APPLE__) && defined(__aarch64__)
        AppleFileArena arena;
        const auto result{arena.Prepare(argv[4], Number(argv[5]))};
        if (!result) {
            std::cerr << "File arena unavailable at " << result.stage << " (errno " << result.native_error << ").\n";
            // Do not start a large heap trial after a file trial's setup fails.
            return 2;
        }
        return Run(mode, count, pressure_mib, &arena.Chunks());
#else
        throw std::runtime_error{"file mode requires native Apple Silicon"};
#endif
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
