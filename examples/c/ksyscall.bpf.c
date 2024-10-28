#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

// setuid x
// setgid x
// setresuid x
// setresgid x
// setreuid x
// setregid x
// capset x
// execve x
// chown x
// fchown x
// lchown x
// chmod x
// fchmod x
// setfsuid
// setfsgid
// unshare
// setns
// clone
// prctl
// capget
// init_module
// finit_module
// delete_module
// mprotect
// mmap
// ptrace
// auditctl
// seccomp

// Tag (PE), syscall, PID, process, uid, gid, ruid, euid, suid, rgid, egid, sgid, pathname, owner, group, fd, mode, fsuid, fsgid, flags, nstype, op, addr, len, prot, ptrace_pid, operation

SEC("ksyscall/setuid")
int BPF_KSYSCALL(setuid_entry, uid_t uid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setuid,%d,%s,%d,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, uid);
    return 0;
}

SEC("ksyscall/setgid")
int BPF_KSYSCALL(setgid_entry, gid_t gid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setgid,%d,%s,?,%d,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, gid);
    return 0;
}

/*
 * setresuid, setresgid - set real, effective, and saved user or group ID
*/
SEC("ksyscall/setresuid")
int BPF_KSYSCALL(setresuid_entry, uid_t ruid, uid_t euid, uid_t suid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setresuid,%d,%s,?,?,%d,%d,%d,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, ruid, euid, suid);
    return 0;
}

/*
 * setresuid, setresgid - set real, effective, and saved user or group ID
*/
SEC("ksyscall/setresgid")
int BPF_KSYSCALL(setresgid_entry, gid_t rgid, gid_t egid, gid_t sgid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setresuid,%d,%s,?,?,?,?,?,%d,%d,%d,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, rgid, egid, sgid);
    return 0;
}

/*
 * setreuid, setregid - set real and/or effective user or group ID
*/
SEC("ksyscall/setreuid")
int BPF_KSYSCALL(setreuid_entry, uid_t ruid, uid_t euid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setreuid,%d,%s,?,?,%d,%d,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, ruid, euid);
    return 0;
}

/*
 * setreuid, setregid - set real and/or effective user or group ID
*/
SEC("ksyscall/setregid")
int BPF_KSYSCALL(setregid_entry, gid_t rgid, gid_t egid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setregid,%d,%s,?,?,?,?,?,%d,%d,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, rgid, egid);
    return 0;
}

/*
 * capget, capset - set/get capabilities of thread(s)
*/
SEC("ksyscall/capset")
int BPF_KSYSCALL(capset_entry, cap_user_header_t hdrp,
                 const cap_user_data_t datap)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,capset,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm);
    return 0;
}

/*
 * execve - execute program
*/
SEC("ksyscall/execve")
int BPF_KSYSCALL(execve_entry, const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[])
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,execve,%d,%s,?,?,?,?,?,?,?,?,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, pathname);
    return 0;
}

/*
 * chown, fchown, lchown, fchownat - change ownership of a file
*/
SEC("ksyscall/chown")
int BPF_KSYSCALL(chown_entry, const char *pathname, uid_t owner, gid_t group)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,chown,%d,%s,?,?,?,?,?,?,?,?,%s,%d,%d,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, pathname, owner, group);
    return 0;
}

/*
 * chown, fchown, lchown, fchownat - change ownership of a file
*/
SEC("ksyscall/fchown")
int BPF_KSYSCALL(fchown_entry, int fd, uid_t owner, gid_t group)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,fchown,%d,%s,?,?,?,?,?,?,?,?,?,%d,%d,%d,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, owner, group, fd);
    return 0;
}

/*
 * chown, fchown, lchown, fchownat - change ownership of a file
*/
SEC("ksyscall/lchown")
int BPF_KSYSCALL(lchown_entry, const char *pathname, uid_t owner, gid_t group)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,lchown,%d,%s,?,?,?,?,?,?,?,?,%s,%d,%d,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, pathname, owner, group);
    return 0;
}

/*
 * chmod, fchmod, fchmodat - change permissions of a file
*/
SEC("ksyscall/chmod")
int BPF_KSYSCALL(chmod_entry, const char *pathname, mode_t mode)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,chmod,%d,%s,?,?,?,?,?,?,?,?,%s,?,?,?,%o,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, pathname, mode);
    return 0;
}

/*
 * chmod, fchmod, fchmodat - change permissions of a file
*/
SEC("ksyscall/fchmod")
int BPF_KSYSCALL(fchmod_entry, int fd, mode_t mode)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,fchmod,%d,%s,?,?,?,?,?,?,?,?,?,?,?,%d,%o,?,?,?,?,?,?,?,?,?,?", caller_pid, comm, fd, mode);
    return 0;
}

/*
 * setfsuid - set user identity used for filesystem checks
*/
SEC("ksyscall/setfsuid")
int BPF_KSYSCALL(setfsuid_entry, uid_t fsuid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setfsuid,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,?,?,?,?,?", caller_pid, comm, fsuid);
    return 0;
}

/*
 * setfsgid - set group identity used for filesystem checks
*/
SEC("ksyscall/setfsgid")
int BPF_KSYSCALL(setfsgid_entry, gid_t fsgid)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setfsgid,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,?,?,?,?", caller_pid, comm, fsgid);
    return 0;
}

/*
 * unshare - disassociate parts of the process execution context
*/
SEC("ksyscall/unshare")
int BPF_KSYSCALL(unshare_entry, int flags)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,unshare,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,?,?,?", caller_pid, comm);
    return 0;
}

/*
 * setns - reassociate thread with a namespace
*/
SEC("ksyscall/setns")
int BPF_KSYSCALL(setns_entry, int fd, int nstype)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,setns,%d,%s,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,%d,?,?,?,?,?,?", caller_pid, comm, fd, nstype);
    return 0;
}

/*
 * clone, __clone2, clone3 - create a child process
*/
SEC("ksyscall/clone")
int BPF_KSYSCALL(clone_entry)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,clone,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm);
    return 0;
}

/*
 * prctl - operations on a process or thread
 *        int prctl(int op, ...
 *               unsigned long arg2, unsigned long arg3,
 *               unsigned long arg4, unsigned long arg5 )
 *
 * Only use op
*/
SEC("ksyscall/prctl")
int BPF_KSYSCALL(prctl_entry, int op)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,prctl,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,?", caller_pid, comm, op);
    return 0;
}

/*
 * capget, capset - set/get capabilities of thread(s)
 *
 * Skip: cap_user_header_t hdrp, cap_user_data_t datap
*/
SEC("ksyscall/capget")
int BPF_KSYSCALL(capget_entry)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,capget,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?", caller_pid, comm);
    return 0;
}

/*
 * mprotect, pkey_mprotect - set protection on a region of memory
*/
SEC("ksyscall/mprotect")
int BPF_KSYSCALL(mprotect_entry, void *addr, size_t len, int prot)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,mprotect,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%p,%u,%d,?,?", caller_pid, comm, addr, len, prot);
    return 0;
}

/*
 * mmap, munmap - map or unmap files or devices into memory
*/
SEC("ksyscall/mmap")
int BPF_KSYSCALL(mmap_entry, void *addr, size_t length, int prot, int flags,
                  int fd, off_t offset)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,mmap,%d,%s,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,?,?,%p,%u,%d,?,?", caller_pid, comm, fd, addr, length, prot);
    return 0;
}

/*
 * ptrace - process trace
 *
 * Skip some
*/
SEC("ksyscall/ptrace")
int BPF_KSYSCALL(ptrace_entry, pid_t pid,
                   void *addr, void *data)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,ptrace,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%p,?,?,%d,?", caller_pid, comm, addr, pid);
    return 0;
}

/*
 * seccomp - operate on Secure Computing state of the process
*/
SEC("ksyscall/seccomp")
int BPF_KSYSCALL(seccomp_entry,  unsigned int operation, unsigned int flags)
{
    char comm[TASK_COMM_LEN];
    __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("PE,seccomp,%d,%s,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,%d,?,?,?,?,?,?,%d", caller_pid, comm, flags, operation);
    return 0;
}






// SEC("ksyscall/tgkill")
// int BPF_KSYSCALL(tgkill_entry, pid_t tgid, pid_t tid, int sig)
// {
//     char comm[TASK_COMM_LEN];
//     __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

//     if (sig == 0) {
//         /*
//             If sig is 0, then no signal is sent, but existence and permission
//             checks are still performed; this can be used to check for the
//             existence of a process ID or process group ID that the caller is
//             permitted to signal.
//         */
//         return 0;
//     }

//     bpf_get_current_comm(&comm, sizeof(comm));
//     bpf_printk(
//         "tgkill syscall called by PID %d (%s) for thread id %d with pid %d and signal %d.",
//         caller_pid, comm, tid, tgid, sig);
//     return 0;
// }

// SEC("ksyscall/kill")
// int BPF_KSYSCALL(kill_entry, pid_t pid, int sig)
// {
//     char comm[TASK_COMM_LEN];
//     __u32 caller_pid = bpf_get_current_pid_tgid() >> 32;

//     if (sig == 0) {
//         /*
//             If sig is 0, then no signal is sent, but existence and permission
//             checks are still performed; this can be used to check for the
//             existence of a process ID or process group ID that the caller is
//             permitted to signal.
//         */
//         return 0;
//     }

//     bpf_get_current_comm(&comm, sizeof(comm));
//     bpf_printk("KILL syscall called by PID %d (%s) for PID %d with signal %d.", caller_pid,
//            comm, pid, sig);
//     return 0;
// }

char _license[] SEC("license") = "GPL";
