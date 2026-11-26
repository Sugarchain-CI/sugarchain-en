#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char *end = NULL;
    errno = 0;
    long pid = strtol(argv[1], &end, 10);
    if (errno || *end || pid <= 0 || pid > INT_MAX) return 2;
    struct rusage_info_v4 usage = {0};
    if (proc_pid_rusage((int)pid, RUSAGE_INFO_V4, (rusage_info_t *)&usage) != 0) return 3;
    printf("{\"physical_footprint_bytes\":%" PRIu64 ",\"resident_bytes\":%" PRIu64
           ",\"pageins\":%" PRIu64 ",\"disk_read_bytes\":%" PRIu64 ",\"disk_written_bytes\":%" PRIu64
           ",\"user_cpu_ns\":%" PRIu64 ",\"system_cpu_ns\":%" PRIu64 "}\n",
           usage.ri_phys_footprint, usage.ri_resident_size, usage.ri_pageins,
           usage.ri_diskio_bytesread, usage.ri_diskio_byteswritten, usage.ri_user_time, usage.ri_system_time);
    return 0;
}
