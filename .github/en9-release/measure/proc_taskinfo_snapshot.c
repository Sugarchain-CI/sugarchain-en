// SDK-backed per-child telemetry for the Intel Mac diagnostic.
#include <errno.h>
#include <inttypes.h>
#include <libproc.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/proc_info.h>
#include <sys/resource.h>

#define TASK_UNSIGNED(X) \
    X(pti_virtual_size) X(pti_resident_size) X(pti_total_user) X(pti_total_system) \
    X(pti_threads_user) X(pti_threads_system)
#define TASK_SIGNED(X) \
    X(pti_policy) X(pti_faults) X(pti_pageins) X(pti_cow_faults) X(pti_messages_sent) \
    X(pti_messages_received) X(pti_syscalls_mach) X(pti_syscalls_unix) X(pti_csw) \
    X(pti_threadnum) X(pti_numrunning)
#define USAGE_FIELDS(X) \
    X(ri_user_time) X(ri_system_time) X(ri_pkg_idle_wkups) X(ri_interrupt_wkups) X(ri_pageins) \
    X(ri_wired_size) X(ri_resident_size) X(ri_phys_footprint) X(ri_proc_start_abstime) \
    X(ri_proc_exit_abstime) X(ri_child_user_time) X(ri_child_system_time) X(ri_child_pkg_idle_wkups) \
    X(ri_child_interrupt_wkups) X(ri_child_pageins) X(ri_child_elapsed_abstime) X(ri_diskio_bytesread) \
    X(ri_diskio_byteswritten) X(ri_cpu_time_qos_default) X(ri_cpu_time_qos_maintenance) \
    X(ri_cpu_time_qos_background) X(ri_cpu_time_qos_utility) X(ri_cpu_time_qos_legacy) \
    X(ri_cpu_time_qos_user_initiated) X(ri_cpu_time_qos_user_interactive) X(ri_billed_system_time) \
    X(ri_serviced_system_time) X(ri_logical_writes) X(ri_lifetime_max_phys_footprint) X(ri_instructions) \
    X(ri_cycles) X(ri_billed_energy) X(ri_serviced_energy) X(ri_interval_max_phys_footprint)

static int read_info(int pid, int flavor, void *buffer, int size)
{
    errno = 0;
    if (proc_pidinfo(pid, flavor, 0, buffer, size) == size) return 0;
    return errno ? errno : EIO;
}

int en9_proc_task_snapshot(int pid, int parent, char *output, size_t capacity)
{
    if (pid <= 0 || parent <= 0 || !output || capacity == 0) return EINVAL;

    struct proc_bsdinfo before = {0}, after = {0};
    int error = read_info(pid, PROC_PIDTBSDINFO, &before, PROC_PIDTBSDINFO_SIZE);
    if (error) return error;
    if (before.pbi_pid != (uint32_t)pid || before.pbi_ppid != (uint32_t)parent) return EPERM;

    struct proc_taskinfo task = {0};
    error = read_info(pid, PROC_PIDTASKINFO, &task, PROC_PIDTASKINFO_SIZE);
    if (error) return error;

    struct rusage_info_v4 usage = {0};
    errno = 0;
    if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&usage) != 0) return errno ? errno : EIO;

    error = read_info(pid, PROC_PIDTBSDINFO, &after, PROC_PIDTBSDINFO_SIZE);
    if (error) return error;
    if (after.pbi_pid != before.pbi_pid || after.pbi_ppid != before.pbi_ppid ||
        after.pbi_start_tvsec != before.pbi_start_tvsec || after.pbi_start_tvusec != before.pbi_start_tvusec ||
        usage.ri_proc_exit_abstime != 0) return ESRCH;

    char uuid[33];
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(usage.ri_uuid); ++i) {
        uuid[2 * i] = hex[usage.ri_uuid[i] >> 4];
        uuid[2 * i + 1] = hex[usage.ri_uuid[i] & 0xf];
    }
    uuid[32] = '\0';
#define FIELD_UNSIGNED(field) "\"" #field "\":%ju,"
#define FIELD_SIGNED(field) "\"" #field "\":%jd,"
#define TASK_UINT_VALUE(field) (uintmax_t)task.field,
#define TASK_INT_VALUE(field) (intmax_t)task.field,
#define USAGE_VALUE(field) (uintmax_t)usage.field,
    int written = snprintf(output, capacity,
        "{\"pid\":%d,\"parent_pid\":%d,\"start_seconds\":%ju,\"start_microseconds\":%ju,"
        "\"task\":{" TASK_UNSIGNED(FIELD_UNSIGNED) TASK_SIGNED(FIELD_SIGNED) "\"pti_priority\":%jd},"
        "\"rusage_info_v4\":{\"ri_uuid\":\"%s\"," USAGE_FIELDS(FIELD_UNSIGNED) "\"ri_runnable_time\":%ju}}",
        pid, parent, (uintmax_t)before.pbi_start_tvsec, (uintmax_t)before.pbi_start_tvusec,
        TASK_UNSIGNED(TASK_UINT_VALUE) TASK_SIGNED(TASK_INT_VALUE) (intmax_t)task.pti_priority,
        uuid, USAGE_FIELDS(USAGE_VALUE) (uintmax_t)usage.ri_runnable_time);
    return written < 0 || (size_t)written >= capacity ? ENOBUFS : 0;
}
