#ifndef SUGARCHAIN_DIAGNOSTIC_MAPPED_POOL_ARENA_H
#define SUGARCHAIN_DIAGNOSTIC_MAPPED_POOL_ARENA_H

#include <support/allocators/pool.h>

#include <cstddef>
#include <cstdint>
#include <span>

class ReservedChunkRange final : public PoolChunkBacking
{
    std::span<std::byte> m_range;
    size_t m_used{0};
    size_t m_returned_chunks{0};

public:
    void SetUp(std::span<std::byte> range) noexcept
    {
        assert(m_range.empty() && m_used == 0);
        m_range = range;
    }

    void* TryAllocateChunk(size_t bytes, size_t alignment) noexcept override
    {
        assert(alignment && !(alignment & (alignment - 1)));
        if (m_range.empty() || bytes == 0) return nullptr;
        const size_t remaining{m_range.size() - m_used};
        const auto address{reinterpret_cast<std::uintptr_t>(m_range.data() + m_used)};
        const size_t padding{(std::uintptr_t{0} - address) & (alignment - 1)};
        if (padding > remaining || bytes > remaining - padding) return nullptr;
        auto* const result{m_range.data() + m_used + padding};
        m_used += padding + bytes;
        ++m_returned_chunks;
        return result;
    }

    bool Owns(const void* address) const noexcept override
    {
        const auto base{reinterpret_cast<std::uintptr_t>(m_range.data())};
        const auto target{reinterpret_cast<std::uintptr_t>(address)};
        return !m_range.empty() && target >= base && target - base < m_used;
    }

    size_t ReturnedChunks() const noexcept { return m_returned_chunks; }
};

#if defined(__APPLE__) && defined(__aarch64__)
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

class AppleFileArena
{
    struct File
    {
        int fd{-1};
        ~File() { if (fd != -1) close(fd); }
    } m_file;
    void* m_address{MAP_FAILED};
    size_t m_length{0};
    ReservedChunkRange m_range;

    static constexpr size_t MAX_BYTES{size_t{9} << 30};
    static constexpr size_t MIN_AVAILABLE_AFTER{size_t{8} << 30};

    static bool HasSpace(const struct statfs& status, size_t bytes)
    {
        if (status.f_bsize == 0 || status.f_bavail <= 0) return false;
        const auto block_size{static_cast<uint64_t>(status.f_bsize)};
        const uint64_t minimum_blocks{bytes / block_size + (bytes % block_size != 0)};
        return status.f_bavail >= minimum_blocks;
    }

public:
    AppleFileArena() = default;
    AppleFileArena(const AppleFileArena&) = delete;
    AppleFileArena& operator=(const AppleFileArena&) = delete;
    ~AppleFileArena()
    {
        if (m_address != MAP_FAILED) munmap(m_address, m_length);
    }

    struct Result
    {
        const char* stage;
        int native_error;
        explicit operator bool() const noexcept { return stage == nullptr; }
    };

    // Must complete before any pool can borrow the arena. All failure paths
    // close the unlinked file and leave the range empty.
    Result Prepare(const std::filesystem::path& folder, size_t bytes)
    {
        assert(m_address == MAP_FAILED && m_file.fd == -1);
        const long page_size{sysconf(_SC_PAGESIZE)};
        if (!folder.is_absolute() || page_size <= 0 || bytes == 0 ||
            bytes > MAX_BYTES || bytes % static_cast<size_t>(page_size) != 0) {
            return {"arena_arguments", EINVAL};
        }
        std::string directory{(folder / "sugarchain-pool.XXXXXX").string()};
        if (!mkdtemp(directory.data())) return {"private_directory", errno};
        File parent{open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)};
        if (parent.fd == -1) {
            const int error{errno};
            rmdir(directory.c_str());
            return {"private_directory_open", error};
        }
        File file{openat(parent.fd, "arena", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)};
        if (file.fd == -1) {
            const int error{errno};
            rmdir(directory.c_str());
            return {"private_file", error};
        }
        if (unlinkat(parent.fd, "arena", 0) != 0) {
            const int error{errno};
            close(file.fd);
            file.fd = -1;
            unlinkat(parent.fd, "arena", 0);
            rmdir(directory.c_str());
            return {"unlink_private_file", error};
        }
        if (rmdir(directory.c_str()) != 0) return {"remove_private_directory", errno};

        struct stat metadata{};
        if (fstat(file.fd, &metadata) != 0) return {"initial_file_stat", errno};
        if (!S_ISREG(metadata.st_mode) || metadata.st_nlink != 0 ||
            (metadata.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != (S_IRUSR | S_IWUSR) ||
            metadata.st_size != 0) {
            return {"private_file_invariants", EINVAL};
        }
        struct statfs volume{};
        if (fstatfs(file.fd, &volume) != 0) return {"initial_volume_stat", errno};
        if (!(volume.f_flags & MNT_LOCAL) || std::strcmp(volume.f_fstypename, "apfs") != 0) {
            return {"local_apfs_required", ENOTSUP};
        }
        if (!HasSpace(volume, bytes + MIN_AVAILABLE_AFTER)) return {"initial_space_budget", ENOSPC};

        fstore_t reservation{};
        reservation.fst_flags = F_ALLOCATEALL;
        reservation.fst_posmode = F_PEOFPOSMODE;
        reservation.fst_offset = 0;
        reservation.fst_length = static_cast<off_t>(bytes);
        if (fcntl(file.fd, F_PREALLOCATE, &reservation) != 0) return {"physical_reservation", errno};
        if (reservation.fst_bytesalloc < static_cast<off_t>(bytes)) return {"short_physical_reservation", ENOSPC};
        if (ftruncate(file.fd, static_cast<off_t>(bytes)) != 0) return {"file_length", errno};
        if (fstat(file.fd, &metadata) != 0) return {"reserved_file_stat", errno};
        if (metadata.st_size != static_cast<off_t>(bytes) ||
            metadata.st_blocks < static_cast<blkcnt_t>(bytes / DEV_BSIZE)) {
            return {"reserved_file_extents", ENOSPC};
        }
        if (fstatfs(file.fd, &volume) != 0) return {"reserved_volume_stat", errno};
        if (!HasSpace(volume, MIN_AVAILABLE_AFTER)) return {"remaining_space_budget", ENOSPC};

        void* const address{mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, file.fd, 0)};
        if (address == MAP_FAILED) return {"mmap_shared", errno};
        m_address = address;
        m_length = bytes;
        m_file.fd = file.fd;
        file.fd = -1;
        m_range.SetUp({static_cast<std::byte*>(address), bytes});
        return {nullptr, 0};
    }

    ReservedChunkRange& Chunks() noexcept { return m_range; }
};
#endif // Apple Silicon

#endif // SUGARCHAIN_DIAGNOSTIC_MAPPED_POOL_ARENA_H
