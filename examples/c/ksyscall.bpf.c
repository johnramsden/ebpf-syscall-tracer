#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16

char _license[] SEC("license") = "GPL";

SEC("ksyscall/read")
int BPF_KSYSCALL(read_entry)
{
    bpf_printk("0");
    return 0;
}

SEC("ksyscall/write")
int BPF_KSYSCALL(write_entry)
{
    bpf_printk("1");
    return 0;
}

SEC("ksyscall/open")
int BPF_KSYSCALL(open_entry)
{
    bpf_printk("2");
    return 0;
}

SEC("ksyscall/close")
int BPF_KSYSCALL(close_entry)
{
    bpf_printk("3");
    return 0;
}

SEC("ksyscall/stat")
int BPF_KSYSCALL(stat_entry)
{
    bpf_printk("4");
    return 0;
}

SEC("ksyscall/fstat")
int BPF_KSYSCALL(fstat_entry)
{
    bpf_printk("5");
    return 0;
}

SEC("ksyscall/lstat")
int BPF_KSYSCALL(lstat_entry)
{
    bpf_printk("6");
    return 0;
}

SEC("ksyscall/poll")
int BPF_KSYSCALL(poll_entry)
{
    bpf_printk("7");
    return 0;
}

SEC("ksyscall/lseek")
int BPF_KSYSCALL(lseek_entry)
{
    bpf_printk("8");
    return 0;
}

SEC("ksyscall/mmap")
int BPF_KSYSCALL(mmap_entry)
{
    bpf_printk("9");
    return 0;
}

SEC("ksyscall/mprotect")
int BPF_KSYSCALL(mprotect_entry)
{
    bpf_printk("10");
    return 0;
}

SEC("ksyscall/munmap")
int BPF_KSYSCALL(munmap_entry)
{
    bpf_printk("11");
    return 0;
}

SEC("ksyscall/brk")
int BPF_KSYSCALL(brk_entry)
{
    bpf_printk("12");
    return 0;
}

SEC("ksyscall/rt_sigaction")
int BPF_KSYSCALL(rt_sigaction_entry)
{
    bpf_printk("13");
    return 0;
}

SEC("ksyscall/rt_sigprocmask")
int BPF_KSYSCALL(rt_sigprocmask_entry)
{
    bpf_printk("14");
    return 0;
}

SEC("ksyscall/rt_sigreturn")
int BPF_KSYSCALL(rt_sigreturn_entry)
{
    bpf_printk("15");
    return 0;
}

SEC("ksyscall/ioctl")
int BPF_KSYSCALL(ioctl_entry)
{
    bpf_printk("16");
    return 0;
}

SEC("ksyscall/pread")
int BPF_KSYSCALL(pread_entry)
{
    bpf_printk("17");
    return 0;
}

SEC("ksyscall/pwrite")
int BPF_KSYSCALL(pwrite_entry)
{
    bpf_printk("18");
    return 0;
}

SEC("ksyscall/readv")
int BPF_KSYSCALL(readv_entry)
{
    bpf_printk("19");
    return 0;
}

SEC("ksyscall/writev")
int BPF_KSYSCALL(writev_entry)
{
    bpf_printk("20");
    return 0;
}

SEC("ksyscall/access")
int BPF_KSYSCALL(access_entry)
{
    bpf_printk("21");
    return 0;
}

SEC("ksyscall/pipe")
int BPF_KSYSCALL(pipe_entry)
{
    bpf_printk("22");
    return 0;
}

SEC("ksyscall/select")
int BPF_KSYSCALL(select_entry)
{
    bpf_printk("23");
    return 0;
}

SEC("ksyscall/sched_yield")
int BPF_KSYSCALL(sched_yield_entry)
{
    bpf_printk("24");
    return 0;
}

SEC("ksyscall/mremap")
int BPF_KSYSCALL(mremap_entry)
{
    bpf_printk("25");
    return 0;
}

SEC("ksyscall/msync")
int BPF_KSYSCALL(msync_entry)
{
    bpf_printk("26");
    return 0;
}

SEC("ksyscall/mincore")
int BPF_KSYSCALL(mincore_entry)
{
    bpf_printk("27");
    return 0;
}

SEC("ksyscall/madvise")
int BPF_KSYSCALL(madvise_entry)
{
    bpf_printk("28");
    return 0;
}

SEC("ksyscall/shmget")
int BPF_KSYSCALL(shmget_entry)
{
    bpf_printk("29");
    return 0;
}

SEC("ksyscall/shmat")
int BPF_KSYSCALL(shmat_entry)
{
    bpf_printk("30");
    return 0;
}

SEC("ksyscall/shmctl")
int BPF_KSYSCALL(shmctl_entry)
{
    bpf_printk("31");
    return 0;
}

SEC("ksyscall/dup")
int BPF_KSYSCALL(dup_entry)
{
    bpf_printk("32");
    return 0;
}

SEC("ksyscall/dup2")
int BPF_KSYSCALL(dup2_entry)
{
    bpf_printk("33");
    return 0;
}

SEC("ksyscall/pause")
int BPF_KSYSCALL(pause_entry)
{
    bpf_printk("34");
    return 0;
}

SEC("ksyscall/nanosleep")
int BPF_KSYSCALL(nanosleep_entry)
{
    bpf_printk("35");
    return 0;
}

SEC("ksyscall/getitimer")
int BPF_KSYSCALL(getitimer_entry)
{
    bpf_printk("36");
    return 0;
}

SEC("ksyscall/alarm")
int BPF_KSYSCALL(alarm_entry)
{
    bpf_printk("37");
    return 0;
}

SEC("ksyscall/setitimer")
int BPF_KSYSCALL(setitimer_entry)
{
    bpf_printk("38");
    return 0;
}

SEC("ksyscall/getpid")
int BPF_KSYSCALL(getpid_entry)
{
    bpf_printk("39");
    return 0;
}

SEC("ksyscall/sendfile")
int BPF_KSYSCALL(sendfile_entry)
{
    bpf_printk("40");
    return 0;
}

SEC("ksyscall/socket")
int BPF_KSYSCALL(socket_entry)
{
    bpf_printk("41");
    return 0;
}

SEC("ksyscall/connect")
int BPF_KSYSCALL(connect_entry)
{
    bpf_printk("42");
    return 0;
}

SEC("ksyscall/accept")
int BPF_KSYSCALL(accept_entry)
{
    bpf_printk("43");
    return 0;
}

SEC("ksyscall/sendto")
int BPF_KSYSCALL(sendto_entry)
{
    bpf_printk("44");
    return 0;
}

SEC("ksyscall/recvfrom")
int BPF_KSYSCALL(recvfrom_entry)
{
    bpf_printk("45");
    return 0;
}

SEC("ksyscall/sendmsg")
int BPF_KSYSCALL(sendmsg_entry)
{
    bpf_printk("46");
    return 0;
}

SEC("ksyscall/recvmsg")
int BPF_KSYSCALL(recvmsg_entry)
{
    bpf_printk("47");
    return 0;
}

SEC("ksyscall/shutdown")
int BPF_KSYSCALL(shutdown_entry)
{
    bpf_printk("48");
    return 0;
}

SEC("ksyscall/bind")
int BPF_KSYSCALL(bind_entry)
{
    bpf_printk("49");
    return 0;
}

SEC("ksyscall/listen")
int BPF_KSYSCALL(listen_entry)
{
    bpf_printk("50");
    return 0;
}

SEC("ksyscall/getsockname")
int BPF_KSYSCALL(getsockname_entry)
{
    bpf_printk("51");
    return 0;
}

SEC("ksyscall/getpeername")
int BPF_KSYSCALL(getpeername_entry)
{
    bpf_printk("52");
    return 0;
}

SEC("ksyscall/socketpair")
int BPF_KSYSCALL(socketpair_entry)
{
    bpf_printk("53");
    return 0;
}

SEC("ksyscall/setsockopt")
int BPF_KSYSCALL(setsockopt_entry)
{
    bpf_printk("54");
    return 0;
}

SEC("ksyscall/getsockopt")
int BPF_KSYSCALL(getsockopt_entry)
{
    bpf_printk("55");
    return 0;
}

SEC("ksyscall/clone")
int BPF_KSYSCALL(clone_entry)
{
    bpf_printk("56");
    return 0;
}

SEC("ksyscall/fork")
int BPF_KSYSCALL(fork_entry)
{
    bpf_printk("57");
    return 0;
}

SEC("ksyscall/vfork")
int BPF_KSYSCALL(vfork_entry)
{
    bpf_printk("58");
    return 0;
}

SEC("ksyscall/execve")
int BPF_KSYSCALL(execve_entry)
{
    bpf_printk("59");
    return 0;
}

SEC("ksyscall/exit")
int BPF_KSYSCALL(exit_entry)
{
    bpf_printk("60");
    return 0;
}

SEC("ksyscall/wait4")
int BPF_KSYSCALL(wait4_entry)
{
    bpf_printk("61");
    return 0;
}

SEC("ksyscall/kill")
int BPF_KSYSCALL(kill_entry)
{
    bpf_printk("62");
    return 0;
}

SEC("ksyscall/uname")
int BPF_KSYSCALL(uname_entry)
{
    bpf_printk("63");
    return 0;
}

SEC("ksyscall/semget")
int BPF_KSYSCALL(semget_entry)
{
    bpf_printk("64");
    return 0;
}

SEC("ksyscall/semop")
int BPF_KSYSCALL(semop_entry)
{
    bpf_printk("65");
    return 0;
}

SEC("ksyscall/semctl")
int BPF_KSYSCALL(semctl_entry)
{
    bpf_printk("66");
    return 0;
}

SEC("ksyscall/shmdt")
int BPF_KSYSCALL(shmdt_entry)
{
    bpf_printk("67");
    return 0;
}

SEC("ksyscall/msgget")
int BPF_KSYSCALL(msgget_entry)
{
    bpf_printk("68");
    return 0;
}

SEC("ksyscall/msgsnd")
int BPF_KSYSCALL(msgsnd_entry)
{
    bpf_printk("69");
    return 0;
}

SEC("ksyscall/msgrcv")
int BPF_KSYSCALL(msgrcv_entry)
{
    bpf_printk("70");
    return 0;
}

SEC("ksyscall/msgctl")
int BPF_KSYSCALL(msgctl_entry)
{
    bpf_printk("71");
    return 0;
}

SEC("ksyscall/fcntl")
int BPF_KSYSCALL(fcntl_entry)
{
    bpf_printk("72");
    return 0;
}

SEC("ksyscall/flock")
int BPF_KSYSCALL(flock_entry)
{
    bpf_printk("73");
    return 0;
}

SEC("ksyscall/fsync")
int BPF_KSYSCALL(fsync_entry)
{
    bpf_printk("74");
    return 0;
}

SEC("ksyscall/fdatasync")
int BPF_KSYSCALL(fdatasync_entry)
{
    bpf_printk("75");
    return 0;
}

SEC("ksyscall/truncate")
int BPF_KSYSCALL(truncate_entry)
{
    bpf_printk("76");
    return 0;
}

SEC("ksyscall/ftruncate")
int BPF_KSYSCALL(ftruncate_entry)
{
    bpf_printk("77");
    return 0;
}

SEC("ksyscall/getdents")
int BPF_KSYSCALL(getdents_entry)
{
    bpf_printk("78");
    return 0;
}

SEC("ksyscall/getcwd")
int BPF_KSYSCALL(getcwd_entry)
{
    bpf_printk("79");
    return 0;
}

SEC("ksyscall/chdir")
int BPF_KSYSCALL(chdir_entry)
{
    bpf_printk("80");
    return 0;
}

SEC("ksyscall/fchdir")
int BPF_KSYSCALL(fchdir_entry)
{
    bpf_printk("81");
    return 0;
}

SEC("ksyscall/rename")
int BPF_KSYSCALL(rename_entry)
{
    bpf_printk("82");
    return 0;
}

SEC("ksyscall/mkdir")
int BPF_KSYSCALL(mkdir_entry)
{
    bpf_printk("83");
    return 0;
}

SEC("ksyscall/rmdir")
int BPF_KSYSCALL(rmdir_entry)
{
    bpf_printk("84");
    return 0;
}

SEC("ksyscall/creat")
int BPF_KSYSCALL(creat_entry)
{
    bpf_printk("85");
    return 0;
}

SEC("ksyscall/link")
int BPF_KSYSCALL(link_entry)
{
    bpf_printk("86");
    return 0;
}

SEC("ksyscall/unlink")
int BPF_KSYSCALL(unlink_entry)
{
    bpf_printk("87");
    return 0;
}

SEC("ksyscall/symlink")
int BPF_KSYSCALL(symlink_entry)
{
    bpf_printk("88");
    return 0;
}

SEC("ksyscall/readlink")
int BPF_KSYSCALL(readlink_entry)
{
    bpf_printk("89");
    return 0;
}

SEC("ksyscall/chmod")
int BPF_KSYSCALL(chmod_entry)
{
    bpf_printk("90");
    return 0;
}

SEC("ksyscall/fchmod")
int BPF_KSYSCALL(fchmod_entry)
{
    bpf_printk("91");
    return 0;
}

SEC("ksyscall/chown")
int BPF_KSYSCALL(chown_entry)
{
    bpf_printk("92");
    return 0;
}

SEC("ksyscall/fchown")
int BPF_KSYSCALL(fchown_entry)
{
    bpf_printk("93");
    return 0;
}

SEC("ksyscall/lchown")
int BPF_KSYSCALL(lchown_entry)
{
    bpf_printk("94");
    return 0;
}

SEC("ksyscall/umask")
int BPF_KSYSCALL(umask_entry)
{
    bpf_printk("95");
    return 0;
}

SEC("ksyscall/gettimeofday")
int BPF_KSYSCALL(gettimeofday_entry)
{
    bpf_printk("96");
    return 0;
}

SEC("ksyscall/getrlimit")
int BPF_KSYSCALL(getrlimit_entry)
{
    bpf_printk("97");
    return 0;
}

SEC("ksyscall/getrusage")
int BPF_KSYSCALL(getrusage_entry)
{
    bpf_printk("98");
    return 0;
}

SEC("ksyscall/sysinfo")
int BPF_KSYSCALL(sysinfo_entry)
{
    bpf_printk("99");
    return 0;
}

SEC("ksyscall/times")
int BPF_KSYSCALL(times_entry)
{
    bpf_printk("100");
    return 0;
}

SEC("ksyscall/ptrace")
int BPF_KSYSCALL(ptrace_entry)
{
    bpf_printk("101");
    return 0;
}

SEC("ksyscall/getuid")
int BPF_KSYSCALL(getuid_entry)
{
    bpf_printk("102");
    return 0;
}

SEC("ksyscall/syslog")
int BPF_KSYSCALL(syslog_entry)
{
    bpf_printk("103");
    return 0;
}

SEC("ksyscall/getgid")
int BPF_KSYSCALL(getgid_entry)
{
    bpf_printk("104");
    return 0;
}

SEC("ksyscall/setuid")
int BPF_KSYSCALL(setuid_entry)
{
    bpf_printk("105");
    return 0;
}

SEC("ksyscall/setgid")
int BPF_KSYSCALL(setgid_entry)
{
    bpf_printk("106");
    return 0;
}

SEC("ksyscall/geteuid")
int BPF_KSYSCALL(geteuid_entry)
{
    bpf_printk("107");
    return 0;
}

SEC("ksyscall/getegid")
int BPF_KSYSCALL(getegid_entry)
{
    bpf_printk("108");
    return 0;
}

SEC("ksyscall/setpgid")
int BPF_KSYSCALL(setpgid_entry)
{
    bpf_printk("109");
    return 0;
}

SEC("ksyscall/getppid")
int BPF_KSYSCALL(getppid_entry)
{
    bpf_printk("110");
    return 0;
}

SEC("ksyscall/getpgrp")
int BPF_KSYSCALL(getpgrp_entry)
{
    bpf_printk("111");
    return 0;
}

SEC("ksyscall/setsid")
int BPF_KSYSCALL(setsid_entry)
{
    bpf_printk("112");
    return 0;
}

SEC("ksyscall/setreuid")
int BPF_KSYSCALL(setreuid_entry)
{
    bpf_printk("113");
    return 0;
}

SEC("ksyscall/setregid")
int BPF_KSYSCALL(setregid_entry)
{
    bpf_printk("114");
    return 0;
}

SEC("ksyscall/getgroups")
int BPF_KSYSCALL(getgroups_entry)
{
    bpf_printk("115");
    return 0;
}

SEC("ksyscall/setgroups")
int BPF_KSYSCALL(setgroups_entry)
{
    bpf_printk("116");
    return 0;
}

SEC("ksyscall/setresuid")
int BPF_KSYSCALL(setresuid_entry)
{
    bpf_printk("117");
    return 0;
}

SEC("ksyscall/getresuid")
int BPF_KSYSCALL(getresuid_entry)
{
    bpf_printk("118");
    return 0;
}

SEC("ksyscall/setresgid")
int BPF_KSYSCALL(setresgid_entry)
{
    bpf_printk("119");
    return 0;
}

SEC("ksyscall/getresgid")
int BPF_KSYSCALL(getresgid_entry)
{
    bpf_printk("120");
    return 0;
}

SEC("ksyscall/getpgid")
int BPF_KSYSCALL(getpgid_entry)
{
    bpf_printk("121");
    return 0;
}

SEC("ksyscall/setfsuid")
int BPF_KSYSCALL(setfsuid_entry)
{
    bpf_printk("122");
    return 0;
}

SEC("ksyscall/setfsgid")
int BPF_KSYSCALL(setfsgid_entry)
{
    bpf_printk("123");
    return 0;
}

SEC("ksyscall/getsid")
int BPF_KSYSCALL(getsid_entry)
{
    bpf_printk("124");
    return 0;
}

SEC("ksyscall/capget")
int BPF_KSYSCALL(capget_entry)
{
    bpf_printk("125");
    return 0;
}

SEC("ksyscall/capset")
int BPF_KSYSCALL(capset_entry)
{
    bpf_printk("126");
    return 0;
}

SEC("ksyscall/rt_sigpending")
int BPF_KSYSCALL(rt_sigpending_entry)
{
    bpf_printk("127");
    return 0;
}

SEC("ksyscall/rt_sigtimedwait")
int BPF_KSYSCALL(rt_sigtimedwait_entry)
{
    bpf_printk("128");
    return 0;
}

SEC("ksyscall/rt_sigqueueinfo")
int BPF_KSYSCALL(rt_sigqueueinfo_entry)
{
    bpf_printk("129");
    return 0;
}

SEC("ksyscall/rt_sigsuspend")
int BPF_KSYSCALL(rt_sigsuspend_entry)
{
    bpf_printk("130");
    return 0;
}

SEC("ksyscall/sigaltstack")
int BPF_KSYSCALL(sigaltstack_entry)
{
    bpf_printk("131");
    return 0;
}

SEC("ksyscall/utime")
int BPF_KSYSCALL(utime_entry)
{
    bpf_printk("132");
    return 0;
}

SEC("ksyscall/mknod")
int BPF_KSYSCALL(mknod_entry)
{
    bpf_printk("133");
    return 0;
}

SEC("ksyscall/uselib")
int BPF_KSYSCALL(uselib_entry)
{
    bpf_printk("134");
    return 0;
}

SEC("ksyscall/personality")
int BPF_KSYSCALL(personality_entry)
{
    bpf_printk("135");
    return 0;
}

SEC("ksyscall/ustat")
int BPF_KSYSCALL(ustat_entry)
{
    bpf_printk("136");
    return 0;
}

SEC("ksyscall/statfs")
int BPF_KSYSCALL(statfs_entry)
{
    bpf_printk("137");
    return 0;
}

SEC("ksyscall/fstatfs")
int BPF_KSYSCALL(fstatfs_entry)
{
    bpf_printk("138");
    return 0;
}

SEC("ksyscall/sysfs")
int BPF_KSYSCALL(sysfs_entry)
{
    bpf_printk("139");
    return 0;
}

SEC("ksyscall/getpriority")
int BPF_KSYSCALL(getpriority_entry)
{
    bpf_printk("140");
    return 0;
}

SEC("ksyscall/setpriority")
int BPF_KSYSCALL(setpriority_entry)
{
    bpf_printk("141");
    return 0;
}

SEC("ksyscall/sched_setparam")
int BPF_KSYSCALL(sched_setparam_entry)
{
    bpf_printk("142");
    return 0;
}

SEC("ksyscall/sched_getparam")
int BPF_KSYSCALL(sched_getparam_entry)
{
    bpf_printk("143");
    return 0;
}

SEC("ksyscall/sched_setscheduler")
int BPF_KSYSCALL(sched_setscheduler_entry)
{
    bpf_printk("144");
    return 0;
}

SEC("ksyscall/sched_getscheduler")
int BPF_KSYSCALL(sched_getscheduler_entry)
{
    bpf_printk("145");
    return 0;
}

SEC("ksyscall/sched_get_priority_max")
int BPF_KSYSCALL(sched_get_priority_max_entry)
{
    bpf_printk("146");
    return 0;
}

SEC("ksyscall/sched_get_priority_min")
int BPF_KSYSCALL(sched_get_priority_min_entry)
{
    bpf_printk("147");
    return 0;
}

SEC("ksyscall/sched_rr_get_interval")
int BPF_KSYSCALL(sched_rr_get_interval_entry)
{
    bpf_printk("148");
    return 0;
}

SEC("ksyscall/mlock")
int BPF_KSYSCALL(mlock_entry)
{
    bpf_printk("149");
    return 0;
}

SEC("ksyscall/munlock")
int BPF_KSYSCALL(munlock_entry)
{
    bpf_printk("150");
    return 0;
}

SEC("ksyscall/mlockall")
int BPF_KSYSCALL(mlockall_entry)
{
    bpf_printk("151");
    return 0;
}

SEC("ksyscall/munlockall")
int BPF_KSYSCALL(munlockall_entry)
{
    bpf_printk("152");
    return 0;
}

SEC("ksyscall/vhangup")
int BPF_KSYSCALL(vhangup_entry)
{
    bpf_printk("153");
    return 0;
}

SEC("ksyscall/modify_ldt")
int BPF_KSYSCALL(modify_ldt_entry)
{
    bpf_printk("154");
    return 0;
}

SEC("ksyscall/pivot_root")
int BPF_KSYSCALL(pivot_root_entry)
{
    bpf_printk("155");
    return 0;
}

SEC("ksyscall/_sysctl")
int BPF_KSYSCALL(_sysctl_entry)
{
    bpf_printk("156");
    return 0;
}

SEC("ksyscall/prctl")
int BPF_KSYSCALL(prctl_entry)
{
    bpf_printk("157");
    return 0;
}

SEC("ksyscall/arch_prctl")
int BPF_KSYSCALL(arch_prctl_entry)
{
    bpf_printk("158");
    return 0;
}

SEC("ksyscall/adjtimex")
int BPF_KSYSCALL(adjtimex_entry)
{
    bpf_printk("159");
    return 0;
}

SEC("ksyscall/setrlimit")
int BPF_KSYSCALL(setrlimit_entry)
{
    bpf_printk("160");
    return 0;
}

SEC("ksyscall/chroot")
int BPF_KSYSCALL(chroot_entry)
{
    bpf_printk("161");
    return 0;
}

SEC("ksyscall/sync")
int BPF_KSYSCALL(sync_entry)
{
    bpf_printk("162");
    return 0;
}

SEC("ksyscall/acct")
int BPF_KSYSCALL(acct_entry)
{
    bpf_printk("163");
    return 0;
}

SEC("ksyscall/settimeofday")
int BPF_KSYSCALL(settimeofday_entry)
{
    bpf_printk("164");
    return 0;
}

SEC("ksyscall/mount")
int BPF_KSYSCALL(mount_entry)
{
    bpf_printk("165");
    return 0;
}

SEC("ksyscall/umount2")
int BPF_KSYSCALL(umount2_entry)
{
    bpf_printk("166");
    return 0;
}

SEC("ksyscall/swapon")
int BPF_KSYSCALL(swapon_entry)
{
    bpf_printk("167");
    return 0;
}

SEC("ksyscall/swapoff")
int BPF_KSYSCALL(swapoff_entry)
{
    bpf_printk("168");
    return 0;
}

SEC("ksyscall/reboot")
int BPF_KSYSCALL(reboot_entry)
{
    bpf_printk("169");
    return 0;
}

SEC("ksyscall/sethostname")
int BPF_KSYSCALL(sethostname_entry)
{
    bpf_printk("170");
    return 0;
}

SEC("ksyscall/setdomainname")
int BPF_KSYSCALL(setdomainname_entry)
{
    bpf_printk("171");
    return 0;
}

SEC("ksyscall/iopl")
int BPF_KSYSCALL(iopl_entry)
{
    bpf_printk("172");
    return 0;
}

SEC("ksyscall/ioperm")
int BPF_KSYSCALL(ioperm_entry)
{
    bpf_printk("173");
    return 0;
}

SEC("ksyscall/create_module")
int BPF_KSYSCALL(create_module_entry)
{
    bpf_printk("174");
    return 0;
}

SEC("ksyscall/init_module")
int BPF_KSYSCALL(init_module_entry)
{
    bpf_printk("175");
    return 0;
}

SEC("ksyscall/delete_module")
int BPF_KSYSCALL(delete_module_entry)
{
    bpf_printk("176");
    return 0;
}

SEC("ksyscall/get_kernel_syms")
int BPF_KSYSCALL(get_kernel_syms_entry)
{
    bpf_printk("177");
    return 0;
}

SEC("ksyscall/query_module")
int BPF_KSYSCALL(query_module_entry)
{
    bpf_printk("178");
    return 0;
}

SEC("ksyscall/quotactl")
int BPF_KSYSCALL(quotactl_entry)
{
    bpf_printk("179");
    return 0;
}

SEC("ksyscall/nfsservctl")
int BPF_KSYSCALL(nfsservctl_entry)
{
    bpf_printk("180");
    return 0;
}

SEC("ksyscall/getpmsg")
int BPF_KSYSCALL(getpmsg_entry)
{
    bpf_printk("181");
    return 0;
}

SEC("ksyscall/putpmsg")
int BPF_KSYSCALL(putpmsg_entry)
{
    bpf_printk("182");
    return 0;
}

SEC("ksyscall/afs_syscall")
int BPF_KSYSCALL(afs_syscall_entry)
{
    bpf_printk("183");
    return 0;
}

SEC("ksyscall/tuxcall")
int BPF_KSYSCALL(tuxcall_entry)
{
    bpf_printk("184");
    return 0;
}

SEC("ksyscall/security")
int BPF_KSYSCALL(security_entry)
{
    bpf_printk("185");
    return 0;
}

SEC("ksyscall/gettid")
int BPF_KSYSCALL(gettid_entry)
{
    bpf_printk("186");
    return 0;
}

SEC("ksyscall/readahead")
int BPF_KSYSCALL(readahead_entry)
{
    bpf_printk("187");
    return 0;
}

SEC("ksyscall/setxattr")
int BPF_KSYSCALL(setxattr_entry)
{
    bpf_printk("188");
    return 0;
}

SEC("ksyscall/lsetxattr")
int BPF_KSYSCALL(lsetxattr_entry)
{
    bpf_printk("189");
    return 0;
}

SEC("ksyscall/fsetxattr")
int BPF_KSYSCALL(fsetxattr_entry)
{
    bpf_printk("190");
    return 0;
}

SEC("ksyscall/getxattr")
int BPF_KSYSCALL(getxattr_entry)
{
    bpf_printk("191");
    return 0;
}

SEC("ksyscall/lgetxattr")
int BPF_KSYSCALL(lgetxattr_entry)
{
    bpf_printk("192");
    return 0;
}

SEC("ksyscall/fgetxattr")
int BPF_KSYSCALL(fgetxattr_entry)
{
    bpf_printk("193");
    return 0;
}

SEC("ksyscall/listxattr")
int BPF_KSYSCALL(listxattr_entry)
{
    bpf_printk("194");
    return 0;
}

SEC("ksyscall/llistxattr")
int BPF_KSYSCALL(llistxattr_entry)
{
    bpf_printk("195");
    return 0;
}

SEC("ksyscall/flistxattr")
int BPF_KSYSCALL(flistxattr_entry)
{
    bpf_printk("196");
    return 0;
}

SEC("ksyscall/removexattr")
int BPF_KSYSCALL(removexattr_entry)
{
    bpf_printk("197");
    return 0;
}

SEC("ksyscall/lremovexattr")
int BPF_KSYSCALL(lremovexattr_entry)
{
    bpf_printk("198");
    return 0;
}

SEC("ksyscall/fremovexattr")
int BPF_KSYSCALL(fremovexattr_entry)
{
    bpf_printk("199");
    return 0;
}

SEC("ksyscall/tkill")
int BPF_KSYSCALL(tkill_entry)
{
    bpf_printk("200");
    return 0;
}

SEC("ksyscall/time")
int BPF_KSYSCALL(time_entry)
{
    bpf_printk("201");
    return 0;
}

SEC("ksyscall/futex")
int BPF_KSYSCALL(futex_entry)
{
    bpf_printk("202");
    return 0;
}

SEC("ksyscall/sched_setaffinity")
int BPF_KSYSCALL(sched_setaffinity_entry)
{
    bpf_printk("203");
    return 0;
}

SEC("ksyscall/sched_getaffinity")
int BPF_KSYSCALL(sched_getaffinity_entry)
{
    bpf_printk("204");
    return 0;
}

SEC("ksyscall/set_thread_area")
int BPF_KSYSCALL(set_thread_area_entry)
{
    bpf_printk("205");
    return 0;
}

SEC("ksyscall/io_setup")
int BPF_KSYSCALL(io_setup_entry)
{
    bpf_printk("206");
    return 0;
}

SEC("ksyscall/io_destroy")
int BPF_KSYSCALL(io_destroy_entry)
{
    bpf_printk("207");
    return 0;
}

SEC("ksyscall/io_getevents")
int BPF_KSYSCALL(io_getevents_entry)
{
    bpf_printk("208");
    return 0;
}

SEC("ksyscall/io_submit")
int BPF_KSYSCALL(io_submit_entry)
{
    bpf_printk("209");
    return 0;
}

SEC("ksyscall/io_cancel")
int BPF_KSYSCALL(io_cancel_entry)
{
    bpf_printk("210");
    return 0;
}

SEC("ksyscall/get_thread_area")
int BPF_KSYSCALL(get_thread_area_entry)
{
    bpf_printk("211");
    return 0;
}

SEC("ksyscall/lookup_dcookie")
int BPF_KSYSCALL(lookup_dcookie_entry)
{
    bpf_printk("212");
    return 0;
}

SEC("ksyscall/epoll_create")
int BPF_KSYSCALL(epoll_create_entry)
{
    bpf_printk("213");
    return 0;
}

SEC("ksyscall/epoll_ctl_old")
int BPF_KSYSCALL(epoll_ctl_old_entry)
{
    bpf_printk("214");
    return 0;
}

SEC("ksyscall/epoll_wait_old")
int BPF_KSYSCALL(epoll_wait_old_entry)
{
    bpf_printk("215");
    return 0;
}

SEC("ksyscall/remap_file_pages")
int BPF_KSYSCALL(remap_file_pages_entry)
{
    bpf_printk("216");
    return 0;
}

SEC("ksyscall/getdents64")
int BPF_KSYSCALL(getdents64_entry)
{
    bpf_printk("217");
    return 0;
}

SEC("ksyscall/set_tid_address")
int BPF_KSYSCALL(set_tid_address_entry)
{
    bpf_printk("218");
    return 0;
}

SEC("ksyscall/restart_syscall")
int BPF_KSYSCALL(restart_syscall_entry)
{
    bpf_printk("219");
    return 0;
}

SEC("ksyscall/semtimedop")
int BPF_KSYSCALL(semtimedop_entry)
{
    bpf_printk("220");
    return 0;
}

SEC("ksyscall/fadvise64")
int BPF_KSYSCALL(fadvise64_entry)
{
    bpf_printk("221");
    return 0;
}

SEC("ksyscall/timer_create")
int BPF_KSYSCALL(timer_create_entry)
{
    bpf_printk("222");
    return 0;
}

SEC("ksyscall/timer_settime")
int BPF_KSYSCALL(timer_settime_entry)
{
    bpf_printk("223");
    return 0;
}

SEC("ksyscall/timer_gettime")
int BPF_KSYSCALL(timer_gettime_entry)
{
    bpf_printk("224");
    return 0;
}

SEC("ksyscall/timer_getoverrun")
int BPF_KSYSCALL(timer_getoverrun_entry)
{
    bpf_printk("225");
    return 0;
}

SEC("ksyscall/timer_delete")
int BPF_KSYSCALL(timer_delete_entry)
{
    bpf_printk("226");
    return 0;
}

SEC("ksyscall/clock_settime")
int BPF_KSYSCALL(clock_settime_entry)
{
    bpf_printk("227");
    return 0;
}

SEC("ksyscall/clock_gettime")
int BPF_KSYSCALL(clock_gettime_entry)
{
    bpf_printk("228");
    return 0;
}

SEC("ksyscall/clock_getres")
int BPF_KSYSCALL(clock_getres_entry)
{
    bpf_printk("229");
    return 0;
}

SEC("ksyscall/clock_nanosleep")
int BPF_KSYSCALL(clock_nanosleep_entry)
{
    bpf_printk("230");
    return 0;
}

SEC("ksyscall/exit_group")
int BPF_KSYSCALL(exit_group_entry)
{
    bpf_printk("231");
    return 0;
}

SEC("ksyscall/epoll_wait")
int BPF_KSYSCALL(epoll_wait_entry)
{
    bpf_printk("232");
    return 0;
}

SEC("ksyscall/epoll_ctl")
int BPF_KSYSCALL(epoll_ctl_entry)
{
    bpf_printk("233");
    return 0;
}

SEC("ksyscall/tgkill")
int BPF_KSYSCALL(tgkill_entry)
{
    bpf_printk("234");
    return 0;
}

SEC("ksyscall/utimes")
int BPF_KSYSCALL(utimes_entry)
{
    bpf_printk("235");
    return 0;
}

SEC("ksyscall/vserver")
int BPF_KSYSCALL(vserver_entry)
{
    bpf_printk("236");
    return 0;
}

SEC("ksyscall/mbind")
int BPF_KSYSCALL(mbind_entry)
{
    bpf_printk("237");
    return 0;
}

SEC("ksyscall/set_mempolicy")
int BPF_KSYSCALL(set_mempolicy_entry)
{
    bpf_printk("238");
    return 0;
}

SEC("ksyscall/get_mempolicy")
int BPF_KSYSCALL(get_mempolicy_entry)
{
    bpf_printk("239");
    return 0;
}

SEC("ksyscall/mq_open")
int BPF_KSYSCALL(mq_open_entry)
{
    bpf_printk("240");
    return 0;
}

SEC("ksyscall/mq_unlink")
int BPF_KSYSCALL(mq_unlink_entry)
{
    bpf_printk("241");
    return 0;
}

SEC("ksyscall/mq_timedsend")
int BPF_KSYSCALL(mq_timedsend_entry)
{
    bpf_printk("242");
    return 0;
}

SEC("ksyscall/mq_timedreceive")
int BPF_KSYSCALL(mq_timedreceive_entry)
{
    bpf_printk("243");
    return 0;
}

SEC("ksyscall/mq_notify")
int BPF_KSYSCALL(mq_notify_entry)
{
    bpf_printk("244");
    return 0;
}

SEC("ksyscall/mq_getsetattr")
int BPF_KSYSCALL(mq_getsetattr_entry)
{
    bpf_printk("245");
    return 0;
}

SEC("ksyscall/kexec_load")
int BPF_KSYSCALL(kexec_load_entry)
{
    bpf_printk("246");
    return 0;
}

SEC("ksyscall/waitid")
int BPF_KSYSCALL(waitid_entry)
{
    bpf_printk("247");
    return 0;
}

SEC("ksyscall/add_key")
int BPF_KSYSCALL(add_key_entry)
{
    bpf_printk("248");
    return 0;
}

SEC("ksyscall/request_key")
int BPF_KSYSCALL(request_key_entry)
{
    bpf_printk("249");
    return 0;
}

SEC("ksyscall/keyctl")
int BPF_KSYSCALL(keyctl_entry)
{
    bpf_printk("250");
    return 0;
}

SEC("ksyscall/ioprio_set")
int BPF_KSYSCALL(ioprio_set_entry)
{
    bpf_printk("251");
    return 0;
}

SEC("ksyscall/ioprio_get")
int BPF_KSYSCALL(ioprio_get_entry)
{
    bpf_printk("252");
    return 0;
}

SEC("ksyscall/inotify_init")
int BPF_KSYSCALL(inotify_init_entry)
{
    bpf_printk("253");
    return 0;
}

SEC("ksyscall/inotify_add_watch")
int BPF_KSYSCALL(inotify_add_watch_entry)
{
    bpf_printk("254");
    return 0;
}

SEC("ksyscall/inotify_rm_watch")
int BPF_KSYSCALL(inotify_rm_watch_entry)
{
    bpf_printk("255");
    return 0;
}

SEC("ksyscall/migrate_pages")
int BPF_KSYSCALL(migrate_pages_entry)
{
    bpf_printk("256");
    return 0;
}

SEC("ksyscall/openat")
int BPF_KSYSCALL(openat_entry)
{
    bpf_printk("257");
    return 0;
}

SEC("ksyscall/mkdirat")
int BPF_KSYSCALL(mkdirat_entry)
{
    bpf_printk("258");
    return 0;
}

SEC("ksyscall/mknodat")
int BPF_KSYSCALL(mknodat_entry)
{
    bpf_printk("259");
    return 0;
}

SEC("ksyscall/fchownat")
int BPF_KSYSCALL(fchownat_entry)
{
    bpf_printk("260");
    return 0;
}

SEC("ksyscall/futimesat")
int BPF_KSYSCALL(futimesat_entry)
{
    bpf_printk("261");
    return 0;
}

SEC("ksyscall/newfstatat")
int BPF_KSYSCALL(newfstatat_entry)
{
    bpf_printk("262");
    return 0;
}

SEC("ksyscall/unlinkat")
int BPF_KSYSCALL(unlinkat_entry)
{
    bpf_printk("263");
    return 0;
}

SEC("ksyscall/renameat")
int BPF_KSYSCALL(renameat_entry)
{
    bpf_printk("264");
    return 0;
}

SEC("ksyscall/linkat")
int BPF_KSYSCALL(linkat_entry)
{
    bpf_printk("265");
    return 0;
}

SEC("ksyscall/symlinkat")
int BPF_KSYSCALL(symlinkat_entry)
{
    bpf_printk("266");
    return 0;
}

SEC("ksyscall/readlinkat")
int BPF_KSYSCALL(readlinkat_entry)
{
    bpf_printk("267");
    return 0;
}

SEC("ksyscall/fchmodat")
int BPF_KSYSCALL(fchmodat_entry)
{
    bpf_printk("268");
    return 0;
}

SEC("ksyscall/faccessat")
int BPF_KSYSCALL(faccessat_entry)
{
    bpf_printk("269");
    return 0;
}

SEC("ksyscall/pselect6")
int BPF_KSYSCALL(pselect6_entry)
{
    bpf_printk("270");
    return 0;
}

SEC("ksyscall/ppoll")
int BPF_KSYSCALL(ppoll_entry)
{
    bpf_printk("271");
    return 0;
}

SEC("ksyscall/unshare")
int BPF_KSYSCALL(unshare_entry)
{
    bpf_printk("272");
    return 0;
}

SEC("ksyscall/set_robust_list")
int BPF_KSYSCALL(set_robust_list_entry)
{
    bpf_printk("273");
    return 0;
}

SEC("ksyscall/get_robust_list")
int BPF_KSYSCALL(get_robust_list_entry)
{
    bpf_printk("274");
    return 0;
}

SEC("ksyscall/splice")
int BPF_KSYSCALL(splice_entry)
{
    bpf_printk("275");
    return 0;
}

SEC("ksyscall/tee")
int BPF_KSYSCALL(tee_entry)
{
    bpf_printk("276");
    return 0;
}

SEC("ksyscall/sync_file_range")
int BPF_KSYSCALL(sync_file_range_entry)
{
    bpf_printk("277");
    return 0;
}

SEC("ksyscall/vmsplice")
int BPF_KSYSCALL(vmsplice_entry)
{
    bpf_printk("278");
    return 0;
}

SEC("ksyscall/move_pages")
int BPF_KSYSCALL(move_pages_entry)
{
    bpf_printk("279");
    return 0;
}

SEC("ksyscall/utimensat")
int BPF_KSYSCALL(utimensat_entry)
{
    bpf_printk("280");
    return 0;
}

SEC("ksyscall/epoll_pwait")
int BPF_KSYSCALL(epoll_pwait_entry)
{
    bpf_printk("281");
    return 0;
}

SEC("ksyscall/signalfd")
int BPF_KSYSCALL(signalfd_entry)
{
    bpf_printk("282");
    return 0;
}

SEC("ksyscall/timerfd_create")
int BPF_KSYSCALL(timerfd_create_entry)
{
    bpf_printk("283");
    return 0;
}

SEC("ksyscall/eventfd")
int BPF_KSYSCALL(eventfd_entry)
{
    bpf_printk("284");
    return 0;
}

SEC("ksyscall/fallocate")
int BPF_KSYSCALL(fallocate_entry)
{
    bpf_printk("285");
    return 0;
}

SEC("ksyscall/timerfd_settime")
int BPF_KSYSCALL(timerfd_settime_entry)
{
    bpf_printk("286");
    return 0;
}

SEC("ksyscall/timerfd_gettime")
int BPF_KSYSCALL(timerfd_gettime_entry)
{
    bpf_printk("287");
    return 0;
}

SEC("ksyscall/accept4")
int BPF_KSYSCALL(accept4_entry)
{
    bpf_printk("288");
    return 0;
}

SEC("ksyscall/signalfd4")
int BPF_KSYSCALL(signalfd4_entry)
{
    bpf_printk("289");
    return 0;
}

SEC("ksyscall/eventfd2")
int BPF_KSYSCALL(eventfd2_entry)
{
    bpf_printk("290");
    return 0;
}

SEC("ksyscall/epoll_create1")
int BPF_KSYSCALL(epoll_create1_entry)
{
    bpf_printk("291");
    return 0;
}

SEC("ksyscall/dup3")
int BPF_KSYSCALL(dup3_entry)
{
    bpf_printk("292");
    return 0;
}

SEC("ksyscall/pipe2")
int BPF_KSYSCALL(pipe2_entry)
{
    bpf_printk("293");
    return 0;
}

SEC("ksyscall/inotify_init1")
int BPF_KSYSCALL(inotify_init1_entry)
{
    bpf_printk("294");
    return 0;
}

SEC("ksyscall/preadv")
int BPF_KSYSCALL(preadv_entry)
{
    bpf_printk("295");
    return 0;
}

SEC("ksyscall/pwritev")
int BPF_KSYSCALL(pwritev_entry)
{
    bpf_printk("296");
    return 0;
}

SEC("ksyscall/rt_tgsigqueueinfo")
int BPF_KSYSCALL(rt_tgsigqueueinfo_entry)
{
    bpf_printk("297");
    return 0;
}

SEC("ksyscall/perf_event_open")
int BPF_KSYSCALL(perf_event_open_entry)
{
    bpf_printk("298");
    return 0;
}

SEC("ksyscall/recvmmsg")
int BPF_KSYSCALL(recvmmsg_entry)
{
    bpf_printk("299");
    return 0;
}

SEC("ksyscall/fanotify_init")
int BPF_KSYSCALL(fanotify_init_entry)
{
    bpf_printk("300");
    return 0;
}

SEC("ksyscall/fanotify_mark")
int BPF_KSYSCALL(fanotify_mark_entry)
{
    bpf_printk("301");
    return 0;
}

SEC("ksyscall/prlimit64")
int BPF_KSYSCALL(prlimit64_entry)
{
    bpf_printk("302");
    return 0;
}

SEC("ksyscall/name_to_handle_at")
int BPF_KSYSCALL(name_to_handle_at_entry)
{
    bpf_printk("303");
    return 0;
}

SEC("ksyscall/open_by_handle_at")
int BPF_KSYSCALL(open_by_handle_at_entry)
{
    bpf_printk("304");
    return 0;
}

SEC("ksyscall/clock_adjtime")
int BPF_KSYSCALL(clock_adjtime_entry)
{
    bpf_printk("305");
    return 0;
}

SEC("ksyscall/syncfs")
int BPF_KSYSCALL(syncfs_entry)
{
    bpf_printk("306");
    return 0;
}

SEC("ksyscall/sendmmsg")
int BPF_KSYSCALL(sendmmsg_entry)
{
    bpf_printk("307");
    return 0;
}

SEC("ksyscall/setns")
int BPF_KSYSCALL(setns_entry)
{
    bpf_printk("308");
    return 0;
}

SEC("ksyscall/getcpu")
int BPF_KSYSCALL(getcpu_entry)
{
    bpf_printk("309");
    return 0;
}

SEC("ksyscall/process_vm_readv")
int BPF_KSYSCALL(process_vm_readv_entry)
{
    bpf_printk("310");
    return 0;
}

SEC("ksyscall/process_vm_writev")
int BPF_KSYSCALL(process_vm_writev_entry)
{
    bpf_printk("311");
    return 0;
}

SEC("ksyscall/kcmp")
int BPF_KSYSCALL(kcmp_entry)
{
    bpf_printk("312");
    return 0;
}

SEC("ksyscall/finit_module")
int BPF_KSYSCALL(finit_module_entry)
{
    bpf_printk("313");
    return 0;
}

SEC("ksyscall/sched_setattr")
int BPF_KSYSCALL(sched_setattr_entry)
{
    bpf_printk("314");
    return 0;
}

SEC("ksyscall/sched_getattr")
int BPF_KSYSCALL(sched_getattr_entry)
{
    bpf_printk("315");
    return 0;
}

SEC("ksyscall/renameat2")
int BPF_KSYSCALL(renameat2_entry)
{
    bpf_printk("316");
    return 0;
}

SEC("ksyscall/seccomp")
int BPF_KSYSCALL(seccomp_entry)
{
    bpf_printk("317");
    return 0;
}

SEC("ksyscall/getrandom")
int BPF_KSYSCALL(getrandom_entry)
{
    bpf_printk("318");
    return 0;
}

SEC("ksyscall/memfd_create")
int BPF_KSYSCALL(memfd_create_entry)
{
    bpf_printk("319");
    return 0;
}

SEC("ksyscall/kexec_file_load")
int BPF_KSYSCALL(kexec_file_load_entry)
{
    bpf_printk("320");
    return 0;
}

SEC("ksyscall/bpf")
int BPF_KSYSCALL(bpf_entry)
{
    bpf_printk("321");
    return 0;
}

SEC("ksyscall/execveat")
int BPF_KSYSCALL(execveat_entry)
{
    bpf_printk("322");
    return 0;
}

SEC("ksyscall/userfaultfd")
int BPF_KSYSCALL(userfaultfd_entry)
{
    bpf_printk("323");
    return 0;
}

SEC("ksyscall/membarrier")
int BPF_KSYSCALL(membarrier_entry)
{
    bpf_printk("324");
    return 0;
}

SEC("ksyscall/mlock2")
int BPF_KSYSCALL(mlock2_entry)
{
    bpf_printk("325");
    return 0;
}

SEC("ksyscall/copy_file_range")
int BPF_KSYSCALL(copy_file_range_entry)
{
    bpf_printk("326");
    return 0;
}

SEC("ksyscall/preadv2")
int BPF_KSYSCALL(preadv2_entry)
{
    bpf_printk("327");
    return 0;
}

SEC("ksyscall/pwritev2")
int BPF_KSYSCALL(pwritev2_entry)
{
    bpf_printk("328");
    return 0;
}

SEC("ksyscall/pkey_mprotect")
int BPF_KSYSCALL(pkey_mprotect_entry)
{
    bpf_printk("329");
    return 0;
}

SEC("ksyscall/pkey_alloc")
int BPF_KSYSCALL(pkey_alloc_entry)
{
    bpf_printk("330");
    return 0;
}

SEC("ksyscall/pkey_free")
int BPF_KSYSCALL(pkey_free_entry)
{
    bpf_printk("331");
    return 0;
}

SEC("ksyscall/statx")
int BPF_KSYSCALL(statx_entry)
{
    bpf_printk("332");
    return 0;
}

SEC("ksyscall/io_pgetevents")
int BPF_KSYSCALL(io_pgetevents_entry)
{
    bpf_printk("333");
    return 0;
}

SEC("ksyscall/rseq")
int BPF_KSYSCALL(rseq_entry)
{
    bpf_printk("334");
    return 0;
}

SEC("ksyscall/pidfd_send_signal")
int BPF_KSYSCALL(pidfd_send_signal_entry)
{
    bpf_printk("424");
    return 0;
}

SEC("ksyscall/io_uring_setup")
int BPF_KSYSCALL(io_uring_setup_entry)
{
    bpf_printk("425");
    return 0;
}

SEC("ksyscall/io_uring_enter")
int BPF_KSYSCALL(io_uring_enter_entry)
{
    bpf_printk("426");
    return 0;
}

SEC("ksyscall/io_uring_register")
int BPF_KSYSCALL(io_uring_register_entry)
{
    bpf_printk("427");
    return 0;
}

SEC("ksyscall/open_tree")
int BPF_KSYSCALL(open_tree_entry)
{
    bpf_printk("428");
    return 0;
}

SEC("ksyscall/move_mount")
int BPF_KSYSCALL(move_mount_entry)
{
    bpf_printk("429");
    return 0;
}

SEC("ksyscall/fsopen")
int BPF_KSYSCALL(fsopen_entry)
{
    bpf_printk("430");
    return 0;
}

SEC("ksyscall/fsconfig")
int BPF_KSYSCALL(fsconfig_entry)
{
    bpf_printk("431");
    return 0;
}

SEC("ksyscall/fsmount")
int BPF_KSYSCALL(fsmount_entry)
{
    bpf_printk("432");
    return 0;
}

SEC("ksyscall/fspick")
int BPF_KSYSCALL(fspick_entry)
{
    bpf_printk("433");
    return 0;
}

SEC("ksyscall/pidfd_open")
int BPF_KSYSCALL(pidfd_open_entry)
{
    bpf_printk("434");
    return 0;
}

SEC("ksyscall/clone3")
int BPF_KSYSCALL(clone3_entry)
{
    bpf_printk("435");
    return 0;
}

SEC("ksyscall/close_range")
int BPF_KSYSCALL(close_range_entry)
{
    bpf_printk("436");
    return 0;
}

SEC("ksyscall/openat2")
int BPF_KSYSCALL(openat2_entry)
{
    bpf_printk("437");
    return 0;
}

SEC("ksyscall/pidfd_getfd")
int BPF_KSYSCALL(pidfd_getfd_entry)
{
    bpf_printk("438");
    return 0;
}

SEC("ksyscall/faccessat2")
int BPF_KSYSCALL(faccessat2_entry)
{
    bpf_printk("439");
    return 0;
}

SEC("ksyscall/process_madvise")
int BPF_KSYSCALL(process_madvise_entry)
{
    bpf_printk("440");
    return 0;
}

SEC("ksyscall/epoll_pwait2")
int BPF_KSYSCALL(epoll_pwait2_entry)
{
    bpf_printk("441");
    return 0;
}

SEC("ksyscall/mount_setattr")
int BPF_KSYSCALL(mount_setattr_entry)
{
    bpf_printk("442");
    return 0;
}

SEC("ksyscall/quotactl_fd")
int BPF_KSYSCALL(quotactl_fd_entry)
{
    bpf_printk("443");
    return 0;
}

SEC("ksyscall/landlock_create_ruleset")
int BPF_KSYSCALL(landlock_create_ruleset_entry)
{
    bpf_printk("444");
    return 0;
}

SEC("ksyscall/landlock_add_rule")
int BPF_KSYSCALL(landlock_add_rule_entry)
{
    bpf_printk("445");
    return 0;
}

SEC("ksyscall/landlock_restrict_self")
int BPF_KSYSCALL(landlock_restrict_self_entry)
{
    bpf_printk("446");
    return 0;
}

SEC("ksyscall/memfd_secret")
int BPF_KSYSCALL(memfd_secret_entry)
{
    bpf_printk("447");
    return 0;
}

SEC("ksyscall/process_mrelease")
int BPF_KSYSCALL(process_mrelease_entry)
{
    bpf_printk("448");
    return 0;
}

SEC("ksyscall/futex_waitv")
int BPF_KSYSCALL(futex_waitv_entry)
{
    bpf_printk("449");
    return 0;
}

SEC("ksyscall/set_mempolicy_home_node")
int BPF_KSYSCALL(set_mempolicy_home_node_entry)
{
    bpf_printk("450");
    return 0;
}

SEC("ksyscall/cachestat")
int BPF_KSYSCALL(cachestat_entry)
{
    bpf_printk("451");
    return 0;
}


char _license[] SEC("license") = "GPL";
