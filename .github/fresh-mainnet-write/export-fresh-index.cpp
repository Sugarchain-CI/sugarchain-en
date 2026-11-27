// Copyright (c) 2026 The Sugarchain En developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <leveldb/db.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_set>

namespace {
namespace fs = std::filesystem;
constexpr unsigned REQUIRED_HASHES{4097}; // Anchor plus the canonical tail.
constexpr unsigned ABSENT_FORKS{23};
constexpr unsigned HASH_COUNT{REQUIRED_HASHES + ABSENT_FORKS};
constexpr size_t VALUE_MAX{512};
constexpr size_t EXPORT_MAX{1U << 20};

void Check(bool condition, const char* detail)
{
    if (!condition) throw std::runtime_error(detail);
}

void PutLittle(std::string& output, unsigned value, unsigned count)
{
    for (unsigned i = 0; i < count; ++i) {
        output.push_back(static_cast<char>(value & 0xff));
        value >>= 8;
    }
}

enum class Presence { OPTIONAL, REQUIRED, ABSENT };

void Record(leveldb::DB& db, std::string& output, const std::string& key, Presence expected)
{
    // LevelDB Get uses mutable internal caches but writes no logical rows.
    leveldb::ReadOptions read;
    read.verify_checksums = true;
    read.fill_cache = false;
    std::string value;
    const auto status{db.Get(read, key, &value)};
    const bool found{status.ok()};
    Check(found || status.IsNotFound(), "LevelDB key lookup failed");
    Check(expected == Presence::OPTIONAL || found == (expected == Presence::REQUIRED), "Unexpected raw key presence");
    Check(key.size() <= 64 && value.size() <= VALUE_MAX && found == !value.empty(),
          "Raw key/value size differs");
    Check(output.size() + key.size() + value.size() + 4 <= EXPORT_MAX, "Raw export size exceeds cap");
    PutLittle(output, found, 1);
    PutLittle(output, static_cast<unsigned>(key.size()), 1);
    PutLittle(output, static_cast<unsigned>(value.size()), 2);
    output += key;
    output += value;
}

void Export(const fs::path& scratch, const fs::path& profile, const fs::path& keys, const fs::path& destination)
{
    Check(scratch.is_absolute() && fs::canonical(scratch) == scratch &&
          profile.is_absolute() && fs::canonical(profile) == profile && profile.parent_path() == scratch,
          "Export requires an exact private case directly under the owned scratch directory");
    constexpr std::array cases{"01-default", "02-bounded32", "03-bounded32", "04-default"};
    bool case_name{false};
    for (const auto* name : cases) case_name |= profile.filename() == name;
    Check(case_name && fs::is_regular_file(fs::symlink_status(profile / ".fresh-mainnet-write-claimed")) &&
          !fs::exists(profile / ".cookie"), "Prepared case lacks a closed ownership receipt");
    const auto index{profile / "blocks" / "index"};
    Check(fs::canonical(index) == index && fs::is_regular_file(fs::symlink_status(index / "CURRENT")),
          "Expected local owned block index directory");
    Check(destination.is_absolute() && fs::symlink_status(destination).type() == fs::file_type::not_found &&
          destination.parent_path() == keys.parent_path() && destination.parent_path() != profile,
          "Use a new external export file next to the request");
    Check(fs::is_regular_file(fs::symlink_status(keys)) && fs::file_size(keys) == 32 * HASH_COUNT,
          "Raw key list has the wrong size");
    std::ifstream input{keys, std::ios::binary};
    Check(input.good(), "Cannot open the pinned key list");

    leveldb::Options options;
    options.create_if_missing = false;
    options.paranoid_checks = true;
    options.max_open_files = 64;
    leveldb::DB* handle{nullptr};
    const auto status{leveldb::DB::Open(options, index.string(), &handle)};
    Check(status.ok() && handle, "Cannot open the owned LevelDB index");
    std::unique_ptr<leveldb::DB> db{handle};

    std::string output{"SCIDX01\n"};
    PutLittle(output, 3 + 2 * HASH_COUNT, 4);
    Record(*db, output, std::string{"\016\000obfuscate_key", 15}, Presence::OPTIONAL);
    std::string file_key{"f"};
    PutLittle(file_key, 169, 4);
    Record(*db, output, file_key, Presence::REQUIRED);
    Record(*db, output, "l", Presence::REQUIRED);

    std::unordered_set<std::string> seen;
    for (unsigned i = 0; i < HASH_COUNT; ++i) {
        std::string hash(32, '\0');
        Check(bool(input.read(hash.data(), hash.size())) && seen.insert(hash).second, "Invalid duplicate proof export key");
        const auto expected{i < REQUIRED_HASHES ? Presence::REQUIRED : Presence::ABSENT};
        Record(*db, output, std::string{"b"} + hash, expected);
        Record(*db, output, std::string{"y"} + hash, expected);
    }
    db.reset();
    std::ofstream file{destination, std::ios::binary | std::ios::out};
    Check(file.is_open() && bool(file.write(output.data(), output.size())), "Cannot write raw evidence");
    file.close();
    Check(file.good(), "Cannot close raw evidence");
}
} // namespace

int main(int argc, char** argv)
{
    if (argc != 5) return 2;
    try {
        Export(argv[1], argv[2], argv[3], argv[4]);
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
