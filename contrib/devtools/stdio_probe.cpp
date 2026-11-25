#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
static double Ms(Clock::duration elapsed) { return std::chrono::duration<double, std::milli>(elapsed).count(); }
static void Require(bool result) { if (!result) throw std::runtime_error("stdio probe I/O failure"); }
static void Run(const fs::path& dir, unsigned mode, unsigned trial)
{
    const bool explicit_buffer{mode == 2};
    const char* label = mode == 0 ? "per-record" : mode == 1 ? "default-batched" : "64KiB-batched";
    std::array<char, 65536> block_buffer, undo_buffer;
    const auto prefix = std::string(label) + "-" + std::to_string(trial);
    const auto block_path = dir/(prefix + "-blk.dat");
    const auto undo_path = dir/(prefix + "-rev.dat");
    FILE* block = std::fopen(block_path.c_str(), "w+b");
    FILE* undo = std::fopen(undo_path.c_str(), "w+b");
    Require(block && undo);
    if (explicit_buffer) {
        Require(std::setvbuf(block, block_buffer.data(), _IOFBF, block_buffer.size()) == 0);
        Require(std::setvbuf(undo, undo_buffer.data(), _IOFBF, undo_buffer.size()) == 0);
    }
    Require(::ftruncate(::fileno(block), 16 * 1024 * 1024) == 0);
    Require(::ftruncate(::fileno(undo), 1024 * 1024) == 0);
    std::array<unsigned char, 160> block_record{};
    std::array<unsigned char, 41> undo_record{};
    size_t block_pending{0}, undo_pending{0};
    Clock::duration write_time{}, flush_time{};
    const auto start = Clock::now();
    for (unsigned i = 0; i < 10000; ++i) {
        block_record[0] = static_cast<unsigned char>(i);
        const auto before_write = Clock::now();
        Require(std::fwrite(block_record.data(), 1, block_record.size(), block) == block_record.size());
        Require(std::fwrite(undo_record.data(), 1, undo_record.size(), undo) == undo_record.size());
        const auto before_flush = Clock::now();
        write_time += before_flush-before_write;
        block_pending += block_record.size();
        undo_pending += undo_record.size();
        if (mode == 0 || block_pending >= 65536) { Require(std::fflush(block) == 0); block_pending = 0; }
        if (mode == 0 || undo_pending >= 65536) { Require(std::fflush(undo) == 0); undo_pending = 0; }
        flush_time += Clock::now()-before_flush;
    }
    Require(std::fflush(block) == 0 && std::fflush(undo) == 0);
    const auto elapsed = Clock::now()-start;
    struct stat info{};
    Require(::fstat(::fileno(block), &info) == 0);
    const auto before_commit = Clock::now();
    Require(::fsync(::fileno(block)) == 0 && ::fsync(::fileno(undo)) == 0);
    const auto commit_time = Clock::now()-before_commit;
#ifdef __APPLE__
    std::printf("STDIO mode=%s trial=%u libc_buffer=%d file_blocksize=%d flags=%04x total_ms=%.3f fwrite_ms=%.3f fflush_ms=%.3f fsync_ms=%.3f\n", label,trial,block->_bf._size,info.st_blksize,block->_flags,Ms(elapsed),Ms(write_time),Ms(flush_time),Ms(commit_time));
#else
    std::printf("STDIO mode=%s trial=%u file_blocksize=%ld total_ms=%.3f fwrite_ms=%.3f fflush_ms=%.3f fsync_ms=%.3f\n", label,trial,static_cast<long>(info.st_blksize),Ms(elapsed),Ms(write_time),Ms(flush_time),Ms(commit_time));
#endif
    // Validate through separate handles while both writers remain open.
    FILE* block_reader = std::fopen(block_path.c_str(), "rb");
    FILE* undo_reader = std::fopen(undo_path.c_str(), "rb");
    Require(block_reader && undo_reader);
    for (unsigned i=0; i<10000; ++i) {
        std::array<unsigned char, 160> block_read{};
        std::array<unsigned char, 41> undo_read{};
        Require(std::fread(block_read.data(),1,block_read.size(),block_reader)==block_read.size());
        Require(std::fread(undo_read.data(),1,undo_read.size(),undo_reader)==undo_read.size());
        block_record[0]=static_cast<unsigned char>(i);
        Require(block_read==block_record && undo_read==undo_record);
    }
    Require(std::fclose(block_reader)==0 && std::fclose(undo_reader)==0);
    Require(std::fclose(block) == 0 && std::fclose(undo) == 0);
    fs::remove(block_path); fs::remove(undo_path);
}
int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    const fs::path dir{argv[1]};fs::create_directories(dir);
    for (unsigned trial=0; trial<3; ++trial) {
        for (unsigned offset=0; offset<3; ++offset) Run(dir,(trial+offset)%3,trial);
    }
    const auto error_path=dir/"error.dat";
    std::array<char,65536> error_buffer;
    FILE* writer=std::fopen(error_path.c_str(),"w+b");
    Require(writer);
    Require(std::setvbuf(writer,error_buffer.data(),_IOFBF,error_buffer.size())==0);
    FILE* reader=std::fopen(error_path.c_str(),"rb");
    Require(reader && ::dup2(::fileno(reader),::fileno(writer))>=0);
    Require(std::fclose(reader)==0);
    const bool rejected=std::fwrite("check",1,5,writer)!=5 || std::fflush(writer)!=0;
    Require(rejected);
    (void)std::fclose(writer);
    fs::remove(error_path);
    std::puts("STDIO readback=PASS injected-write-error=PASS");
}
