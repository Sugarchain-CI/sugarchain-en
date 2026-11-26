#define main original_pool_probe_main
#include "pool_probe.cpp"
#undef main

#if defined(__APPLE__) && defined(__aarch64__)
#include <mach/mach.h>
#include <mach/mach_vm.h>

struct AppleFileArenaLifecycle
{
    static int Descriptor(const AppleFileArena& arena) { return arena.m_file.fd; }
    static mach_vm_address_t Address(const AppleFileArena& arena)
    {
        return reinterpret_cast<std::uintptr_t>(arena.m_address);
    }
    static size_t Length(const AppleFileArena& arena) { return arena.m_length; }
};

namespace {
constexpr size_t OBJECTS{8192};
constexpr size_t FULL_BYTES{16 << 20};
constexpr size_t MIXED_BYTES{2 * CHUNK_BYTES};

bool HasMapping(mach_vm_address_t address, size_t bytes, bool require_writable_cover)
{
    auto region{address};
    mach_vm_size_t length{0};
    mach_port_t object{MACH_PORT_NULL};
    vm_region_basic_info_data_64_t information{};
    mach_msg_type_number_t count{VM_REGION_BASIC_INFO_COUNT_64};
    const auto code{mach_vm_region(mach_task_self(), &region, &length, VM_REGION_BASIC_INFO_64,
        reinterpret_cast<vm_region_info_t>(&information), &count, &object)};
    if (object != MACH_PORT_NULL) Require(mach_port_deallocate(mach_task_self(), object) == KERN_SUCCESS, "region object port release");
    if (code == KERN_INVALID_ADDRESS || code == KERN_NO_SPACE) return false;
    Require(code == KERN_SUCCESS && count == VM_REGION_BASIC_INFO_COUNT_64, "unexpected native VM region status");
    if (!require_writable_cover) {
        // A later region can identify an unreleased part within the range.
        return region > address ? region - address < bytes : address - region < length;
    }
    return region <= address && address - region < length && bytes <= length - (address - region) &&
        (information.protection & VM_PROT_WRITE) != 0;
}

int FileCase(std::string_view mode, const std::filesystem::path& scratch, size_t bytes)
{
    int descriptor{-1};
    mach_vm_address_t address{0};
    size_t allocated_bytes{0};
    {
        AppleFileArena arena;
        const auto result{arena.Prepare(scratch, bytes)};
        if (!result) {
            std::cout << "{\"status\":\"file_refused\",\"stage\":\"" << result.stage
                      << "\",\"native_errno\":" << result.native_error << "}\n";
            return 2;
        }
        descriptor = AppleFileArenaLifecycle::Descriptor(arena);
        address = AppleFileArenaLifecycle::Address(arena);
        const auto span{AppleFileArenaLifecycle::Length(arena)};
        Require(span == bytes && HasMapping(address, span, true), "native writable mapped extent");
        struct stat backing{};
        Require(fstat(descriptor, &backing) == 0 && S_ISREG(backing.st_mode) && backing.st_nlink == 0 &&
                (backing.st_mode & 0777) == 0600 && backing.st_size == static_cast<off_t>(bytes), "private fd identity and logical length");
        Require(backing.st_blocks >= static_cast<blkcnt_t>(bytes / DEV_BSIZE), "physical blocks reserved");
        allocated_bytes = static_cast<size_t>(backing.st_blocks) * DEV_BSIZE;
        const int flags{fcntl(descriptor, F_GETFD)};
        Require(flags >= 0 && (flags & FD_CLOEXEC), "backing is close-on-exec");
        Require(std::filesystem::is_empty(scratch), "temporary names removed before allocation");

        const long page_size{sysconf(_SC_PAGESIZE)};
        Require(page_size > 0 && bytes % static_cast<size_t>(page_size) == 0, "actual native page size");
        auto* const mapped{reinterpret_cast<unsigned char*>(address)};
        mapped[bytes - 1] = 0xa7;
        Require(msync(mapped + bytes - static_cast<size_t>(page_size), static_cast<size_t>(page_size), MS_SYNC) == 0,
                "native shared-mapping writeback");
        unsigned char sentinel{0};
        Require(pread(descriptor, &sentinel, sizeof(sentinel), static_cast<off_t>(bytes - 1)) == 1 && sentinel == 0xa7,
                "descriptor sees mapped bytes");
        CheckFreelistFallback();
        Require(Run(mode, OBJECTS, 0, &arena.Chunks()) == 0, "allocator verification failed");
        Require(HasMapping(address, span, true) && fcntl(descriptor, F_GETFD) >= 0, "owner lives through borrower retirement");
    }
    errno = 0;
    Require(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF, "backing descriptor closed");
    Require(!HasMapping(address, bytes, false), "owned virtual mapping released");
    Require(std::filesystem::is_empty(scratch), "no scratch pathname after retirement");
    std::cout << "{\"status\":\"lifecycle_verified\",\"reserved_bytes\":" << bytes
              << ",\"physical_bytes\":" << allocated_bytes
              << ",\"fd_mode_0600\":true,\"unlinked\":true,\"cloexec\":true,\"shared_readback\":true,"
                 "\"owned_through_borrowers\":true,\"fd_closed\":true,\"mapping_released\":true,\"no_temp_paths\":true}\n";
    return 0;
}
} // namespace
#endif

int main(int argc, char** argv)
{
#if defined(__APPLE__) && defined(__aarch64__)
    try {
        Require(argc == 3, "expected one bounded lifecycle case and an owned scratch path");
        const std::string_view mode{argv[1]};
        const std::filesystem::path scratch{argv[2]};
        Require(scratch.is_absolute() && scratch.lexically_normal() == scratch, "absolute normalized scratch path");
        if (mode == "heap") {
            CheckFreelistFallback();
            return Run(mode, OBJECTS, 0, nullptr);
        }
        if (mode == "mixed") return FileCase(mode, scratch, MIXED_BYTES);
        if (mode == "file") return FileCase(mode, scratch, FULL_BYTES);
        if (mode == "bad-size") return FileCase(mode, scratch, FULL_BYTES - 1);
        throw std::runtime_error{"unknown lifecycle case"};
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
#else
    static_cast<void>(argc);
    static_cast<void>(argv);
    std::cerr << "File lifecycle only runs on native Apple Silicon.\n";
    return 2;
#endif
}
