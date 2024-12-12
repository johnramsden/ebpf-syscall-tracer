#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

// Set:
// sysctl kernel.bpf_stats_enabled=1

char _license[] SEC("license") = "GPL";

SEC("ksyscall/open")
int BPF_KSYSCALL(open_entry, const char *pathname)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    if (__builtin_memcmp(comm, "read_lat.py", 11) != 0) {
        return 0;
    }

    bpf_printk("READMETRIC %s", pathname);
    return 0;
}
