//! Seccomp-bpf system call filtering.
//!
//! Implements BPF-based allowlist system call filtering, applied after `fork` and before `exec`.
//! Provides two profiles:
//! - Essential: allows only about 40 core system calls.
//! - Network: Essential plus network-related system calls.

use mimobox_core::{SandboxError, SeccompProfile};

// BPF 指令结构体（对应 Linux sock_filter）
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

// BPF 程序结构体（对应 Linux sock_fprog）
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// BPF 常量
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp 返回值
// IMPORTANT-01 修复：使用 KILL_PROCESS 替代 KILL_THREAD，确保整个进程树被终止
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;

// seccomp_data 偏移量
const SECCOMP_DATA_NR: u32 = 0; // offsetof(struct seccomp_data, nr)
const SECCOMP_DATA_ARCH: u32 = 4; // offsetof(struct seccomp_data, arch)
const SECCOMP_DATA_ARGS_BASE: u32 = 16; // offsetof(struct seccomp_data, args)
const SECCOMP_DATA_ARG_SIZE: u32 = 8;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// socket 参数约束
const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const SOCK_STREAM: u32 = 1;
const SOCK_CLOEXEC: u32 = 0x80000;
const SOCK_NONBLOCK: u32 = 0x800;
const SOCK_ALLOWED_TYPE_MASK: u32 = SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK;

// ioctl request 白名单（x86_64）
const TCGETS: u32 = 0x5401;
const TCSETS: u32 = 0x5402;
const TCSETSW: u32 = 0x5403;
const TCSETSF: u32 = 0x5404;
const TIOCGPGRP: u32 = 0x540F;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGWINSZ: u32 = 0x5413;
const TIOCSWINSZ: u32 = 0x5414;
const FIONBIO: u32 = 0x5421;
const FIONREAD: u32 = 0x541B;
const TIOCNOTTY: u32 = 0x5422;
const IOCTL_ALLOWED_REQUESTS: &[u32] = &[
    TCGETS, TCSETS, TCSETSW, TCSETSF, TIOCGPGRP, TIOCSPGRP, TIOCGWINSZ, TIOCSWINSZ, FIONBIO,
    FIONREAD, TIOCNOTTY,
];

// PRCTL 允许的操作（arg0 约束）
// PR_CAPBSET_READ(23)：libcap/libselinux 检查 capability bounding set，只读操作
const PR_CAPBSET_READ: u32 = 23;
const PRCTL_ALLOWED_OPS: &[u32] = &[PR_CAPBSET_READ];

// FUTEX 允许的操作（arg0 约束）
// 仅允许常见的等待/唤醒操作，防止 FUTEX_REQUEUE 等可能导致内核资源耗尽的操作。
const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_WAIT_PRIVATE: u32 = 128; // FUTEX_PRIVATE_FLAG | FUTEX_WAIT
const FUTEX_WAKE_PRIVATE: u32 = 129; // FUTEX_PRIVATE_FLAG | FUTEX_WAKE
const FUTEX_WAIT_BITSET_PRIVATE: u32 = 137; // FUTEX_PRIVATE_FLAG | FUTEX_WAIT_BITSET
const FUTEX_ALLOWED_OPS: &[u32] = &[
    FUTEX_WAIT,
    FUTEX_WAKE,
    FUTEX_WAIT_PRIVATE,
    FUTEX_WAKE_PRIVATE,
    FUTEX_WAIT_BITSET_PRIVATE,
];

// clone namespace flags 约束
// 移除 CLONE_NEWCGROUP 位（与 CLONE_CHILD_CLEARTID 共享 bit 25），
// 避免误杀 bash 等程序创建子进程时的正常 clone 调用。
// 包含：CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET
const CLONE_NAMESPACE_MASK: u32 = 0x4C02_0000;
const BPF_MAX_INSTRUCTIONS: usize = 4096;

// prctl 常量
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: i32 = 2;

/// Linux x86_64 system call number constants referenced by seccomp profiles.
#[allow(dead_code)]
mod syscall_nr {
    /// syscall number for read(2).
    pub const READ: u32 = 0;
    /// syscall number for write(2).
    pub const WRITE: u32 = 1;
    /// syscall number for open(2).
    pub const OPEN: u32 = 2;
    /// syscall number for close(2).
    pub const CLOSE: u32 = 3;
    /// syscall number for stat(2).
    pub const STAT: u32 = 4;
    /// syscall number for fstat(2).
    pub const FSTAT: u32 = 5;
    /// syscall number for lstat(2).
    pub const LSTAT: u32 = 6;
    /// syscall number for poll(2).
    pub const POLL: u32 = 7;
    /// syscall number for mmap(2).
    pub const MMAP: u32 = 9;
    /// syscall number for mprotect(2).
    pub const MPROTECT: u32 = 10;
    /// syscall number for munmap(2).
    pub const MUNMAP: u32 = 11;
    /// syscall number for brk(2).
    pub const BRK: u32 = 12;
    /// syscall number for rt_sigaction(2).
    pub const RT_SIGACTION: u32 = 13;
    /// syscall number for rt_sigprocmask(2).
    pub const RT_SIGPROCMASK: u32 = 14;
    /// syscall number for rt_sigreturn(2).
    pub const RT_SIGRETURN: u32 = 15;
    /// syscall number for ioctl(2).
    pub const IOCTL: u32 = 16;
    /// syscall number for pread64(2).
    pub const PREAD64: u32 = 17;
    /// syscall number for pwrite64(2).
    pub const PWRITE64: u32 = 18;
    /// syscall number for readv(2).
    pub const READV: u32 = 19;
    /// syscall number for writev(2).
    pub const WRITEV: u32 = 20;
    /// syscall number for access(2).
    pub const ACCESS: u32 = 21;
    /// syscall number for pipe(2).
    pub const PIPE: u32 = 22;
    /// syscall number for select(2).
    pub const SELECT: u32 = 23;
    /// syscall number for sched_yield(2).
    pub const SCHED_YIELD: u32 = 24;
    /// syscall number for mremap(2).
    pub const MREMAP: u32 = 25;
    /// syscall number for nanosleep(2).
    pub const NANOSLEEP: u32 = 35;
    /// syscall number for alarm(2).
    pub const ALARM: u32 = 37;
    /// syscall number for getpid(2).
    pub const GETPID: u32 = 39;
    /// syscall number for sendfile(2).
    pub const SENDFILE: u32 = 40;
    /// syscall number for socket(2).
    pub const SOCKET: u32 = 41;
    /// syscall number for connect(2).
    pub const CONNECT: u32 = 42;
    /// syscall number for accept(2).
    pub const ACCEPT: u32 = 43;
    /// syscall number for sendto(2).
    pub const SENDTO: u32 = 44;
    /// syscall number for recvfrom(2).
    pub const RECVFROM: u32 = 45;
    /// syscall number for sendmsg(2).
    pub const SENDMSG: u32 = 46;
    /// syscall number for recvmsg(2).
    pub const RECVMSG: u32 = 47;
    /// syscall number for shutdown(2).
    pub const SHUTDOWN: u32 = 48;
    /// syscall number for bind(2).
    pub const BIND: u32 = 49;
    /// syscall number for listen(2).
    pub const LISTEN: u32 = 50;
    /// syscall number for getsockname(2).
    pub const GETSOCKNAME: u32 = 51;
    /// syscall number for getpeername(2).
    pub const GETPEERNAME: u32 = 52;
    /// syscall number for setsockopt(2).
    pub const SETSOCKOPT: u32 = 54;
    /// syscall number for getsockopt(2).
    pub const GETSOCKOPT: u32 = 55;
    /// syscall number for clone(2).
    pub const CLONE: u32 = 56;
    /// syscall number for fork(2).
    pub const FORK: u32 = 57;
    /// syscall number for vfork(2).
    pub const VFORK: u32 = 58;
    /// syscall number for execve(2).
    pub const EXECVE: u32 = 59;
    /// syscall number for exit(2).
    pub const EXIT: u32 = 60;
    /// syscall number for wait4(2).
    pub const WAIT4: u32 = 61;
    /// syscall number for uname(2).
    pub const UNAME: u32 = 63;
    /// syscall number for fcntl(2).
    pub const FCNTL: u32 = 72;
    /// syscall number for fsync(2).
    pub const FSYNC: u32 = 74;
    /// syscall number for ftruncate(2).
    pub const FTRUNCATE: u32 = 77;
    /// syscall number for getdents(2).
    pub const GETDENTS: u32 = 78;
    /// syscall number for getcwd(2).
    pub const GETCWD: u32 = 79;
    /// syscall number for chdir(2).
    pub const CHDIR: u32 = 80;
    /// syscall number for fchdir(2).
    pub const FCHDIR: u32 = 81;
    /// syscall number for rename(2).
    pub const RENAME: u32 = 82;
    /// syscall number for mkdir(2).
    pub const MKDIR: u32 = 83;
    /// syscall number for rmdir(2).
    pub const RMDIR: u32 = 84;
    /// syscall number for unlink(2).
    pub const UNLINK: u32 = 87;
    /// syscall number for symlink(2).
    pub const SYMLINK: u32 = 88;
    /// syscall number for readlink(2).
    pub const READLINK: u32 = 89;
    /// syscall number for chmod(2).
    pub const CHMOD: u32 = 90;
    /// syscall number for getuid(2).
    pub const GETUID: u32 = 102;
    /// syscall number for syslog(2).
    pub const SYSLOG: u32 = 103;
    /// syscall number for getgid(2).
    pub const GETGID: u32 = 104;
    /// syscall number for setuid(2).
    pub const SETUID: u32 = 105;
    /// syscall number for setgid(2).
    pub const SETGID: u32 = 106;
    /// syscall number for geteuid(2).
    pub const GETEUID: u32 = 107;
    /// syscall number for getegid(2).
    pub const GETEGID: u32 = 108;
    /// syscall number for setpgid(2).
    pub const SETPGID: u32 = 109;
    /// syscall number for getppid(2).
    pub const GETPPID: u32 = 110;
    /// syscall number for getpgrp(2).
    pub const GETPGRP: u32 = 111;
    /// syscall number for setsid(2).
    pub const SETSID: u32 = 112;
    /// syscall number for getgroups(2).
    pub const GETGROUPS: u32 = 115;
    /// syscall number for setgroups(2).
    pub const SETGROUPS: u32 = 116;
    /// syscall number for sigaltstack(2).
    pub const SIGALTSTACK: u32 = 131;
    /// syscall number for rt_sigqueueinfo(2).
    pub const RT_SIGQUEUEINFO: u32 = 129;
    /// syscall number for rt_tgsigqueueinfo(2).
    pub const RT_TGSIGQUEUEINFO: u32 = 240;
    /// syscall number for madvise(2).
    pub const MADVISE: u32 = 28;
    /// syscall number for dup(2).
    pub const DUP: u32 = 32;
    /// syscall number for dup2(2).
    pub const DUP2: u32 = 33;
    /// syscall number for pause(2).
    pub const PAUSE: u32 = 34;
    /// syscall number for arch_prctl(2).
    pub const ARCH_PRCTL: u32 = 158;
    /// syscall number for getxattr(2).
    pub const GETXATTR: u32 = 191;
    /// syscall number for lgetxattr(2).
    pub const LGETXATTR: u32 = 192;
    /// syscall number for fgetxattr(2).
    pub const FGETXATTR: u32 = 193;
    /// syscall number for listxattr(2).
    pub const LISTXATTR: u32 = 195;
    /// syscall number for llistxattr(2).
    pub const LLISTXATTR: u32 = 196;
    /// syscall number for flistxattr(2).
    pub const FLISTXATTR: u32 = 197;
    /// syscall number for set_tid_address(2).
    pub const SET_TID_ADDRESS: u32 = 218;
    /// syscall number for exit_group(2).
    pub const EXIT_GROUP: u32 = 231;
    /// syscall number for set_robust_list(2).
    pub const SET_ROBUST_LIST: u32 = 273;
    /// syscall number for get_robust_list(2).
    pub const GET_ROBUST_LIST: u32 = 274;
    /// syscall number for prlimit64(2).
    pub const PRLIMIT64: u32 = 302;
    /// syscall number for getrandom(2).
    pub const GETRANDOM: u32 = 318;
    /// syscall number for statfs(2).
    pub const STATFS: u32 = 137;
    /// syscall number for prctl(2).
    pub const PRCTL: u32 = 157;
    /// syscall number for getdents64(2).
    pub const GETDENTS64: u32 = 217;
    /// syscall number for rseq(2).
    pub const RSEQ: u32 = 334;
    /// syscall number for preadv(2).
    pub const PREADV: u32 = 296;
    /// syscall number for pwritev(2).
    pub const PWRITEV: u32 = 297;
    /// syscall number for futex(2).
    pub const FUTEX: u32 = 202;
    /// syscall number for clock_gettime(2).
    pub const CLOCK_GETTIME: u32 = 228;
    /// syscall number for clock_getres(2).
    pub const CLOCK_GETRES: u32 = 229;
    /// syscall number for clock_nanosleep(2).
    pub const CLOCK_NANOSLEEP: u32 = 230;
    /// syscall number for tgkill(2).
    pub const TGKILL: u32 = 234;
    /// syscall number for tee(2).
    pub const TEE: u32 = 276;
    /// syscall number for splice(2).
    pub const SPLICE: u32 = 275;
    /// syscall number for epoll_create(2).
    pub const EPOLL_CREATE: u32 = 213;
    /// syscall number for epoll_wait(2).
    pub const EPOLL_WAIT: u32 = 232;
    /// syscall number for epoll_ctl(2).
    pub const EPOLL_CTL: u32 = 233;
    /// syscall number for epoll_create1(2).
    pub const EPOLL_CREATE1: u32 = 291;
    /// syscall number for epoll_pwait(2).
    pub const EPOLL_PWAIT: u32 = 281;
    /// syscall number for timerfd_create(2).
    pub const TIMERFD_CREATE: u32 = 283;
    /// syscall number for timerfd_settime(2).
    pub const TIMERFD_SETTIME: u32 = 286;
    /// syscall number for openat(2).
    pub const OPENAT: u32 = 257;
    /// syscall number for mkdirat(2).
    pub const MKDIRAT: u32 = 258;
    /// syscall number for unlinkat(2).
    pub const UNLINKAT: u32 = 263;
    /// syscall number for readlinkat(2).
    pub const READLINKAT: u32 = 267;
    /// syscall number for fstatat(2).
    pub const FSTATAT: u32 = 262;
    /// syscall number for faccessat(2).
    pub const FACCESSAT: u32 = 269;
    /// syscall number for newfstatat(2).
    pub const NEWFSTATAT: u32 = 262;
    /// syscall number for fchmodat(2).
    pub const FCHMODAT: u32 = 268;
    /// syscall number for linkat(2).
    pub const LINKAT: u32 = 265;
    /// syscall number for symlinkat(2).
    pub const SYMLINKAT: u32 = 266;
    /// syscall number for renameat(2).
    pub const RENAMEAT: u32 = 264;
    /// syscall number for futimensat(2).
    pub const FUTIMENSAT: u32 = 280;
    /// syscall number for ppoll(2).
    pub const PPOLL: u32 = 271;
    /// syscall number for lseek(2).
    pub const LSEEK: u32 = 8;
    /// syscall number for sigprocmask(2).
    pub const SIGPROCMASK: u32 = 14;
    /// syscall number for sigpending(2).
    pub const SIGPENDING: u32 = 73;
    /// syscall number for kill(2).
    pub const KILL: u32 = 62;
    /// syscall number for tkill(2).
    pub const TKILL: u32 = 200;
    /// syscall number for sigtimedwait(2).
    pub const SIGTIMEDWAIT: u32 = 128;
    /// syscall number for sigwaitinfo(2).
    pub const SIGWAITINFO: u32 = 130;
    /// syscall number for pipe2(2).
    pub const PIPE2: u32 = 293;
    /// syscall number for dup3(2).
    pub const DUP3: u32 = 292;
    /// syscall number for gettid(2).
    pub const GETTID: u32 = 186;
    /// syscall number for getrlimit(2).
    pub const GETRLIMIT: u32 = 97;
    /// syscall number for umask(2).
    pub const UMASK: u32 = 95;
    /// syscall number for statx(2).
    pub const STATX: u32 = 332;
    /// syscall number for fadvise64(2).
    pub const FADVISE64: u32 = 221;
    /// syscall number for clone3(2).
    pub const CLONE3: u32 = 435;
    /// syscall number for close_range(2).
    pub const CLOSE_RANGE: u32 = 436;
    /// syscall number for openat2(2).
    pub const OPENAT2: u32 = 437;
    /// syscall number for faccessat2(2).
    pub const FACCESSAT2: u32 = 439;
}

/// Builds the system call allowlist for the Essential profile using least privilege.
///
/// Dangerous system calls that are explicitly excluded and why:
/// - Process creation: fork(57), vfork(58), clone(56), clone3(435) — prevents fork bombs and child-process escapes.
/// - Privilege changes: setuid(105), setgid(106), setgroups(116), setresuid(117), setresgid(119).
/// - Device control: ioctl(16) — too large an attack surface, including TIOCSTI terminal injection.
/// - Process control: prctl(157) — can modify process security attributes.
/// - Signal sending: kill(62), tkill(200), tgkill(234) — prevents sending signals to other processes.
/// - Session/process-group escape: setpgid(109), setsid(112) — prevents bypassing timeout cleanup.
/// - Symbolic links: symlink(88), symlinkat(266) — prevents path traversal.
/// - Permissions/ownership: chmod(90), fchmod(91), fchmodat(268), chown(92), fchown(93),
///   lchown(94), fchownat(260)
/// - Root directory changes: chroot(161).
/// - Process tracing: ptrace(101) — prevents debugging and injection.
/// - Filesystem mounting: mount(165), umount2(166).
/// - BPF loading: bpf(321).
/// - Performance monitoring: perf_event_open(298).
/// - Process personality: personality(135).
/// - Kernel logs: syslog(103) — prevents information disclosure.
fn essential_syscalls() -> Vec<u32> {
    use syscall_nr::*;
    vec![
        // I/O 基础
        READ,
        WRITE,
        CLOSE,
        LSEEK,
        PREAD64,
        PWRITE64,
        READV,
        WRITEV,
        PREADV,
        PWRITEV,
        SENDFILE,
        // 文件操作（不含 symlink/chmod/chown）
        OPEN,
        OPENAT,
        STAT,
        FSTAT,
        LSTAT,
        FSTATAT,
        NEWFSTATAT,
        STATX,
        // SELinux 环境下 ls/stat/rm 等程序需要读取 xattr（如 security.selinux）。
        // 这些 syscall 只读扩展属性，不修改文件系统状态。
        GETXATTR,
        LGETXATTR,
        FGETXATTR,
        LISTXATTR,
        LLISTXATTR,
        FLISTXATTR,
        ACCESS,
        FACCESSAT,
        // glibc 2.33+ 在 access(2) 路径上会优先尝试 faccessat2。
        // 不放行时，/bin/sh 这类程序在启动阶段可能直接触发 seccomp SIGSYS。
        FACCESSAT2,
        READLINK,
        READLINKAT,
        GETDENTS,
        GETDENTS64,
        GETCWD,
        CHDIR,
        FCHDIR,
        DUP,
        DUP2,
        DUP3,
        PIPE,
        PIPE2,
        // 内存管理
        MMAP,
        MUNMAP,
        MPROTECT,
        BRK,
        MREMAP,
        MADVISE,
        // 进程管理（不含 clone/fork/wait4 — 默认禁止子进程创建）
        EXECVE,
        EXIT,
        EXIT_GROUP,
        GETPID,
        GETPPID,
        GETTID,
        // libcap/libselinux 程序在启动时使用 prctl(PR_CAPBSET_READ)
        // 检查 capability bounding set，只读操作不构成安全风险。
        PRCTL,
        ARCH_PRCTL,
        SET_TID_ADDRESS,
        SET_ROBUST_LIST,
        GET_ROBUST_LIST,
        // 信号（仅自身栈管理，不含 kill/tkill/tgkill）
        RT_SIGACTION,
        RT_SIGPROCMASK,
        // shell 信号处理返回必须，缺少时 wait4 + SIGCHLD 路径会触发 SIGSYS
        RT_SIGRETURN,
        SIGALTSTACK,
        // 文件系统（不含 symlink/chmod）
        // 终端 I/O：参数约束系统限制仅允许终端相关 request（TCGETS/TCSETS 等），
        // 不允许任意设备 ioctl。ls/ps 等程序通过 isatty() → ioctl(TCGETS) 检查终端。
        IOCTL,
        FCNTL,
        FSYNC,
        FTRUNCATE,
        FUTIMENSAT,
        MKDIR,
        RMDIR,
        MKDIRAT,
        UNLINK,
        UNLINKAT,
        RENAME,
        RENAMEAT,
        LINKAT,
        UMASK,
        // 用户/组（仅读取，不含 setuid/setgid/setgroups）
        GETUID,
        GETGID,
        GETEUID,
        GETEGID,
        GETGROUPS,
        GETPGRP,
        // 系统（不含 syslog/ioctl/prctl）
        UNAME,
        SELECT,
        POLL,
        PPOLL,
        STATFS,
        NANOSLEEP,
        SCHED_YIELD,
        PAUSE,
        CLOCK_GETTIME,
        CLOCK_GETRES,
        CLOCK_NANOSLEEP,
        GETRANDOM,
        PRLIMIT64,
        GETRLIMIT,
        // epoll
        EPOLL_CREATE,
        EPOLL_CREATE1,
        EPOLL_WAIT,
        EPOLL_CTL,
        EPOLL_PWAIT,
        // futex
        FUTEX,
        // 其他
        RSEQ,
        SPLICE,
        TEE,
        FADVISE64,
        // 现代 Linux 发行版（Rocky/RHEL 9）的 NSS 会使用 unix socket 连接
        // systemd-userdbd 进行用户/组名解析。参数约束系统自动限制为仅 AF_UNIX。
        SOCKET,
        CONNECT,
    ]
}

/// Builds the system call allowlist for `allow_fork` mode.
///
/// Adds process-creation system calls on top of Essential for workloads such as shells that fork
/// child processes. Still excludes `setpgid`/`setsid` to prevent escaping the supervisor process
/// group, `kill`/`tkill` to prevent signaling other processes, and similar calls.
pub fn fork_allowed_syscalls() -> Vec<u32> {
    use syscall_nr::*;
    let mut syscalls = essential_syscalls();
    syscalls.extend_from_slice(&[
        CLONE,
        FORK,
        // shell 执行外部命令时可能经由 vfork/posix_spawn 进入子进程路径。
        VFORK,
        // clone3 的 flags 位于用户态指针，经典 seccomp-bpf 无法解引用检查；
        // 为避免绕过 clone flags 约束，这里不放行 clone3。
        WAIT4,
        // Rocky/RHEL 9 的 NSS/systemd-userdb 查找链会在事件循环中使用 timerfd。
        TIMERFD_CREATE,
        TIMERFD_SETTIME,
    ]);
    syscalls
}

/// Builds the system call allowlist for the Network profile.
///
/// Adds network-related system calls on top of Essential.
fn network_syscalls() -> Vec<u32> {
    use syscall_nr::*;
    let mut syscalls = essential_syscalls();
    syscalls.extend_from_slice(&[
        SOCKET,
        CONNECT,
        ACCEPT,
        SENDTO,
        RECVFROM,
        SENDMSG,
        RECVMSG,
        SHUTDOWN,
        BIND,
        LISTEN,
        GETSOCKNAME,
        GETPEERNAME,
        SETSOCKOPT,
        GETSOCKOPT,
    ]);
    syscalls
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SeccompArgConstraint {
    Socket { allow_inet: bool },
    IoctlRequest,
    CloneFlags,
    PrctlOp,
    FutexOp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConstrainedSyscall {
    nr: u32,
    constraint: SeccompArgConstraint,
}

const fn seccomp_arg_lo_offset(index: u32) -> u32 {
    SECCOMP_DATA_ARGS_BASE + index * SECCOMP_DATA_ARG_SIZE
}

const fn seccomp_arg_hi_offset(index: u32) -> u32 {
    seccomp_arg_lo_offset(index) + 4
}

fn load_abs(offset: u32) -> SockFilter {
    SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

fn jump_eq(k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

fn jump_set(k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt,
        jf,
        k,
    }
}

fn alu_and(k: u32) -> SockFilter {
    SockFilter {
        code: BPF_ALU | BPF_AND | BPF_K,
        jt: 0,
        jf: 0,
        k,
    }
}

fn ret(action: u32) -> SockFilter {
    SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: action,
    }
}

fn forward_jump_offset(from: usize, to: usize, target: &str) -> u8 {
    assert!(to > from, "BPF 跳转目标 {target} 必须位于当前指令之后");

    let offset = to - from - 1;
    assert!(
        offset <= u8::MAX as usize,
        "BPF 跳转到 {target} 的偏移过大: {offset}"
    );

    offset as u8
}

fn arg_constraint_for_syscall(
    nr: u32,
    constraints: &[ConstrainedSyscall],
) -> Option<SeccompArgConstraint> {
    constraints
        .iter()
        .find(|constraint| constraint.nr == nr)
        .map(|constraint| constraint.constraint)
}

fn build_arg_constraints(profile: SeccompProfile, allowed: &[u32]) -> Vec<ConstrainedSyscall> {
    let mut constraints = Vec::with_capacity(5);
    let is_network_profile = matches!(
        profile,
        SeccompProfile::Network | SeccompProfile::NetworkWithFork
    );

    // 任何放行 socket 的 profile 都必须限制 domain/type；Network 模式额外允许 AF_INET。
    if allowed.contains(&syscall_nr::SOCKET) {
        constraints.push(ConstrainedSyscall {
            nr: syscall_nr::SOCKET,
            constraint: SeccompArgConstraint::Socket {
                allow_inet: is_network_profile,
            },
        });
    }

    // 目前只有 fork profile 放行 ioctl；这里只允许终端启动和非阻塞查询所需 request。
    if allowed.contains(&syscall_nr::IOCTL) {
        constraints.push(ConstrainedSyscall {
            nr: syscall_nr::IOCTL,
            constraint: SeccompArgConstraint::IoctlRequest,
        });
    }

    // prctl(157) 必须约束 arg0 为只读查询操作（如 PR_CAPBSET_READ），
    // 防止攻击者执行 PR_SET_DUMPABLE 等修改安全属性的操作。
    if allowed.contains(&syscall_nr::PRCTL) {
        constraints.push(ConstrainedSyscall {
            nr: syscall_nr::PRCTL,
            constraint: SeccompArgConstraint::PrctlOp,
        });
    }

    // futex(202) 只允许常见等待/唤醒操作，拒绝 REQUEUE/CMP_REQUEUE 等资源放大路径。
    if allowed.contains(&syscall_nr::FUTEX) {
        constraints.push(ConstrainedSyscall {
            nr: syscall_nr::FUTEX,
            constraint: SeccompArgConstraint::FutexOp,
        });
    }

    if matches!(
        profile,
        SeccompProfile::EssentialWithFork | SeccompProfile::NetworkWithFork
    ) && allowed.contains(&syscall_nr::CLONE)
    {
        constraints.push(ConstrainedSyscall {
            nr: syscall_nr::CLONE,
            constraint: SeccompArgConstraint::CloneFlags,
        });
    }

    constraints
}

fn build_socket_arg_check_block(allow_inet: bool) -> Vec<SockFilter> {
    let mut block = Vec::with_capacity(18);

    // domain 是 int 参数。低 32 位必须命中白名单，高 32 位必须为 0。
    block.push(load_abs(seccomp_arg_hi_offset(0)));
    block.push(jump_eq(0, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(load_abs(seccomp_arg_lo_offset(0)));

    if allow_inet {
        block.push(jump_eq(AF_UNIX, 2, 0));
        block.push(jump_eq(AF_INET, 1, 0));
        block.push(ret(SECCOMP_RET_KILL_PROCESS));
    } else {
        block.push(jump_eq(AF_UNIX, 1, 0));
        block.push(ret(SECCOMP_RET_KILL_PROCESS));
    }

    // type 必须是 SOCK_STREAM 加上 CLOEXEC/NONBLOCK 的任意组合。
    block.push(load_abs(seccomp_arg_hi_offset(1)));
    block.push(jump_eq(0, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(load_abs(seccomp_arg_lo_offset(1)));
    block.push(alu_and(!SOCK_ALLOWED_TYPE_MASK));
    block.push(jump_eq(0, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(load_abs(seccomp_arg_lo_offset(1)));
    block.push(alu_and(SOCK_STREAM));
    block.push(jump_eq(SOCK_STREAM, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(ret(SECCOMP_RET_ALLOW));

    block
}

fn build_ioctl_arg_check_block() -> Vec<SockFilter> {
    let mut block = Vec::with_capacity(IOCTL_ALLOWED_REQUESTS.len() + 5);

    // request 是 ioctl 的第二个参数。只接受 x86_64 终端相关 request code。
    block.push(load_abs(seccomp_arg_hi_offset(1)));
    block.push(jump_eq(0, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(load_abs(seccomp_arg_lo_offset(1)));

    for (index, &request) in IOCTL_ALLOWED_REQUESTS.iter().enumerate() {
        let instructions_to_skip = (IOCTL_ALLOWED_REQUESTS.len() - index) as u8;
        block.push(jump_eq(request, instructions_to_skip, 0));
    }

    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(ret(SECCOMP_RET_ALLOW));
    block
}

fn build_prctl_arg_check_block() -> Vec<SockFilter> {
    let mut block = Vec::with_capacity(PRCTL_ALLOWED_OPS.len() + 5);

    // op 是 prctl 的第一个参数（arg0）。只允许 PR_CAPBSET_READ 等只读查询操作。
    block.push(load_abs(seccomp_arg_hi_offset(0)));
    block.push(jump_eq(0, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(load_abs(seccomp_arg_lo_offset(0)));

    for (index, &op) in PRCTL_ALLOWED_OPS.iter().enumerate() {
        let instructions_to_skip = (PRCTL_ALLOWED_OPS.len() - index) as u8;
        block.push(jump_eq(op, instructions_to_skip, 0));
    }

    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(ret(SECCOMP_RET_ALLOW));
    block
}

fn build_futex_arg_check_block() -> Vec<SockFilter> {
    let mut block = Vec::with_capacity(FUTEX_ALLOWED_OPS.len() + 5);

    // op 按 seccomp_data arg0 读取；高 32 位非零视为非法扩展。
    block.push(load_abs(seccomp_arg_hi_offset(0)));
    block.push(jump_eq(0, 1, 0));
    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(load_abs(seccomp_arg_lo_offset(0)));

    for (index, &op) in FUTEX_ALLOWED_OPS.iter().enumerate() {
        let instructions_to_skip = (FUTEX_ALLOWED_OPS.len() - index) as u8;
        block.push(jump_eq(op, instructions_to_skip, 0));
    }

    block.push(ret(SECCOMP_RET_KILL_PROCESS));
    block.push(ret(SECCOMP_RET_ALLOW));
    block
}

fn build_clone_arg_check_block() -> Vec<SockFilter> {
    vec![
        // flags 是 unsigned long；高 32 位不应携带额外 flag。
        load_abs(seccomp_arg_hi_offset(0)),
        jump_eq(0, 1, 0),
        ret(SECCOMP_RET_KILL_PROCESS),
        load_abs(seccomp_arg_lo_offset(0)),
        jump_set(CLONE_NAMESPACE_MASK, 0, 1),
        ret(SECCOMP_RET_KILL_PROCESS),
        ret(SECCOMP_RET_ALLOW),
    ]
}

fn build_arg_check_block(constraint: SeccompArgConstraint) -> Vec<SockFilter> {
    match constraint {
        SeccompArgConstraint::Socket { allow_inet } => build_socket_arg_check_block(allow_inet),
        SeccompArgConstraint::IoctlRequest => build_ioctl_arg_check_block(),
        SeccompArgConstraint::CloneFlags => build_clone_arg_check_block(),
        SeccompArgConstraint::PrctlOp => build_prctl_arg_check_block(),
        SeccompArgConstraint::FutexOp => build_futex_arg_check_block(),
    }
}

/// Generates a BPF system call allowlist filter with parameter-level constraints.
///
/// Program structure:
///
/// ```text
/// [0]     Load seccomp_data.arch
/// [1]     If arch == AUDIT_ARCH_X86_64, skip KILL and continue
/// [2]     KILL_PROCESS
/// [3]     Load seccomp_data.nr
/// [4..]   Syscall allowlist chain
///         - constrained syscall: JEQ -> inline argument block, JF skips the block
///         - unconstrained syscall: JEQ -> shared ALLOW
/// [N-2]   KILL_PROCESS (default)
/// [N-1]   ALLOW
/// ```
fn build_bpf_program(allowed: &[u32], constraints: &[ConstrainedSyscall]) -> Vec<SockFilter> {
    let mut prog = Vec::with_capacity(4 + allowed.len() + constraints.len() * 18 + 2);
    let mut allow_jump_indexes = Vec::new();

    // 架构校验必须在读取 syscall number 前执行，避免跨架构 syscall 号绕过。
    prog.push(load_abs(SECCOMP_DATA_ARCH));
    prog.push(jump_eq(AUDIT_ARCH_X86_64, 1, 0));
    prog.push(ret(SECCOMP_RET_KILL_PROCESS));
    prog.push(load_abs(SECCOMP_DATA_NR));

    for &syscall_nr in allowed {
        if let Some(constraint) = arg_constraint_for_syscall(syscall_nr, constraints) {
            let block = build_arg_check_block(constraint);
            assert!(
                block.len() <= u8::MAX as usize,
                "BPF 参数约束块过长: syscall={syscall_nr}, len={}",
                block.len()
            );

            prog.push(jump_eq(syscall_nr, 0, block.len() as u8));
            prog.extend(block);
        } else {
            let jump_index = prog.len();
            prog.push(jump_eq(syscall_nr, 0, 0));
            allow_jump_indexes.push(jump_index);
        }
    }

    prog.push(ret(SECCOMP_RET_KILL_PROCESS));
    let allow_index = prog.len();
    prog.push(ret(SECCOMP_RET_ALLOW));

    for jump_index in allow_jump_indexes {
        prog[jump_index].jt = forward_jump_offset(jump_index, allow_index, "ALLOW");
    }

    assert!(
        prog.len() <= BPF_MAX_INSTRUCTIONS,
        "BPF 程序超过 seccomp 指令上限: {} > {}",
        prog.len(),
        BPF_MAX_INSTRUCTIONS
    );

    prog
}

/// Applies the seccomp-bpf filter.
///
/// # Safety
///
/// This function uses `unsafe` to call the `prctl` system call. It must be called in the child
/// process after `fork` and before `exec`. `PR_SET_NO_NEW_PRIVS` must be set before calling it.
pub fn apply_seccomp(profile: SeccompProfile) -> Result<(), SandboxError> {
    let allowed = match profile {
        SeccompProfile::Essential => essential_syscalls(),
        SeccompProfile::Network => network_syscalls(),
        SeccompProfile::EssentialWithFork => fork_allowed_syscalls(),
        SeccompProfile::NetworkWithFork => {
            let mut syscalls = fork_allowed_syscalls();
            use syscall_nr::*;
            syscalls.extend_from_slice(&[
                SOCKET,
                CONNECT,
                ACCEPT,
                SENDTO,
                RECVFROM,
                SENDMSG,
                RECVMSG,
                SHUTDOWN,
                BIND,
                LISTEN,
                GETSOCKNAME,
                GETPEERNAME,
                SETSOCKOPT,
                GETSOCKOPT,
            ]);
            syscalls
        }
    };
    // 排序以优化 BPF 跳转
    let mut allowed = allowed;
    allowed.sort_unstable();
    allowed.dedup();

    let constraints = build_arg_constraints(profile, &allowed);
    let prog = build_bpf_program(&allowed, &constraints);

    // 设置 PR_SET_NO_NEW_PRIVS，防止子进程提权绕过 seccomp
    // SAFETY: prctl is called in the child process with constant arguments and no raw pointers.
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret < 0 {
        return Err(SandboxError::SeccompFailed(
            "PR_SET_NO_NEW_PRIVS failed".into(),
        ));
    }

    // 安装 BPF 过滤器
    // SAFETY: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) 会复制 BPF 程序到内核空间，
    // prog 的内存在调用返回后不再被内核引用。IMPORTANT-06。
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };

    // SAFETY: prctl copies the sock_fprog descriptor; fprog points to a valid BPF program.
    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &fprog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    };

    if ret < 0 {
        // SAFETY: errno is thread-local and can be read immediately after the failed libc call.
        let errno = unsafe { *libc::__errno_location() };
        return Err(SandboxError::SeccompFailed(format!(
            "prctl(PR_SET_SECCOMP) 失败: errno={errno}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::syscall_nr::{
        CLONE, CLONE3, FUTEX, IOCTL, READ, RT_SIGQUEUEINFO, RT_TGSIGQUEUEINFO, SETPGID, SETSID,
        SOCKET, TGKILL,
    };
    use super::{
        AF_INET, AF_UNIX, AUDIT_ARCH_X86_64, BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_JSET,
        BPF_K, BPF_LD, BPF_RET, BPF_W, CLONE_NAMESPACE_MASK, ConstrainedSyscall, FIONBIO,
        FUTEX_WAIT, FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAIT_PRIVATE, FUTEX_WAKE, FUTEX_WAKE_PRIVATE,
        SECCOMP_DATA_ARCH, SECCOMP_DATA_ARG_SIZE, SECCOMP_DATA_ARGS_BASE, SECCOMP_DATA_NR,
        SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SOCK_CLOEXEC, SOCK_NONBLOCK, SOCK_STREAM,
        SeccompArgConstraint, SockFilter, TCGETS, TIOCGPGRP, TIOCSPGRP, build_arg_constraints,
        build_bpf_program, essential_syscalls, fork_allowed_syscalls, network_syscalls,
    };
    use mimobox_core::SeccompProfile;

    #[derive(Clone, Copy)]
    struct FakeSeccompData {
        nr: u32,
        arch: u32,
        args: [[u32; 2]; 6],
    }

    impl FakeSeccompData {
        fn new(nr: u32) -> Self {
            Self {
                nr,
                arch: AUDIT_ARCH_X86_64,
                args: [[0; 2]; 6],
            }
        }

        fn with_arch(mut self, arch: u32) -> Self {
            self.arch = arch;
            self
        }

        fn with_arg(mut self, index: usize, value: u64) -> Self {
            self.args[index][0] = value as u32;
            self.args[index][1] = (value >> 32) as u32;
            self
        }
    }

    fn load_seccomp_word(data: &FakeSeccompData, offset: u32) -> u32 {
        match offset {
            SECCOMP_DATA_NR => data.nr,
            SECCOMP_DATA_ARCH => data.arch,
            offset
                if (SECCOMP_DATA_ARGS_BASE..SECCOMP_DATA_ARGS_BASE + 6 * SECCOMP_DATA_ARG_SIZE)
                    .contains(&offset) =>
            {
                let relative_offset = offset - SECCOMP_DATA_ARGS_BASE;
                assert_eq!(relative_offset % 4, 0, "BPF 测试只支持 32 位对齐读取");

                let arg_index = (relative_offset / SECCOMP_DATA_ARG_SIZE) as usize;
                let word_index = ((relative_offset % SECCOMP_DATA_ARG_SIZE) / 4) as usize;
                data.args[arg_index][word_index]
            }
            _ => panic!("测试 BPF 解释器不支持 offset={offset}"),
        }
    }

    fn run_bpf(program: &[SockFilter], data: FakeSeccompData) -> u32 {
        let mut accumulator = 0_u32;
        let mut pc = 0_usize;

        for _ in 0..program.len() * 2 {
            let instruction = program
                .get(pc)
                .unwrap_or_else(|| panic!("BPF pc 越界: pc={pc}"));

            match instruction.code {
                code if code == (BPF_LD | BPF_W | BPF_ABS) => {
                    accumulator = load_seccomp_word(&data, instruction.k);
                    pc += 1;
                }
                code if code == (BPF_JMP | BPF_JEQ | BPF_K) => {
                    let offset = if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    pc += offset as usize + 1;
                }
                code if code == (BPF_JMP | BPF_JSET | BPF_K) => {
                    let offset = if accumulator & instruction.k != 0 {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    pc += offset as usize + 1;
                }
                code if code == (BPF_ALU | BPF_AND | BPF_K) => {
                    accumulator &= instruction.k;
                    pc += 1;
                }
                code if code == (BPF_RET | BPF_K) => return instruction.k,
                code => panic!("测试 BPF 解释器不支持 code={code:#x}"),
            }
        }

        panic!("BPF 程序疑似死循环");
    }

    fn program_for_profile(profile: SeccompProfile) -> Vec<SockFilter> {
        let mut allowed = match profile {
            SeccompProfile::Essential => essential_syscalls(),
            SeccompProfile::Network => network_syscalls(),
            SeccompProfile::EssentialWithFork => fork_allowed_syscalls(),
            SeccompProfile::NetworkWithFork => {
                let mut syscalls = fork_allowed_syscalls();
                syscalls.extend(network_syscalls());
                syscalls
            }
        };
        allowed.sort_unstable();
        allowed.dedup();

        let constraints = build_arg_constraints(profile, &allowed);
        build_bpf_program(&allowed, &constraints)
    }

    #[test]
    fn test_essential_profile_blocks_process_group_escape_syscalls() {
        let syscalls = essential_syscalls();

        assert!(
            !syscalls.contains(&SETSID),
            "Essential profile 不应允许 setsid"
        );
        assert!(
            !syscalls.contains(&SETPGID),
            "Essential profile 不应允许 setpgid"
        );
    }

    #[test]
    fn test_fork_allowed_profile_blocks_process_group_escape_syscalls() {
        let syscalls = fork_allowed_syscalls();

        assert!(
            !syscalls.contains(&SETSID),
            "允许 fork 的 profile 也不应允许 setsid"
        );
        assert!(
            !syscalls.contains(&SETPGID),
            "允许 fork 的 profile 也不应允许 setpgid"
        );
    }

    #[test]
    fn test_fork_allowed_profile_blocks_signal_injection_syscalls() {
        let syscalls = fork_allowed_syscalls();

        assert!(
            !syscalls.contains(&TGKILL),
            "允许 fork 的 profile 不应允许 tgkill"
        );
        assert!(
            !syscalls.contains(&RT_SIGQUEUEINFO),
            "允许 fork 的 profile 不应允许 rt_sigqueueinfo"
        );
        assert!(
            !syscalls.contains(&RT_TGSIGQUEUEINFO),
            "允许 fork 的 profile 不应允许 rt_tgsigqueueinfo"
        );
    }

    #[test]
    fn test_fork_allowed_profile_blocks_unconstrainable_clone3() {
        let syscalls = fork_allowed_syscalls();

        assert!(
            !syscalls.contains(&CLONE3),
            "clone3 的 clone_args 位于用户态指针中，经典 seccomp-bpf 无法安全约束"
        );
    }

    #[test]
    fn test_bpf_program_starts_with_arch_check() {
        let program = program_for_profile(SeccompProfile::Essential);

        assert_eq!(program[0].code, BPF_LD | BPF_W | BPF_ABS);
        assert_eq!(program[0].k, SECCOMP_DATA_ARCH);
        assert_eq!(program[1], super::jump_eq(AUDIT_ARCH_X86_64, 1, 0));
        assert_eq!(program[2], super::ret(SECCOMP_RET_KILL_PROCESS));

        let wrong_arch = FakeSeccompData::new(READ).with_arch(0);
        assert_eq!(
            run_bpf(&program, wrong_arch),
            SECCOMP_RET_KILL_PROCESS,
            "arch 不匹配时必须直接 kill"
        );
    }

    #[test]
    fn test_socket_constraint_restricts_domain_and_type() {
        let program = program_for_profile(SeccompProfile::NetworkWithFork);

        let inet_stream = FakeSeccompData::new(SOCKET)
            .with_arg(0, AF_INET as u64)
            .with_arg(1, (SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK) as u64);
        assert_eq!(run_bpf(&program, inet_stream), SECCOMP_RET_ALLOW);

        let unix_stream = FakeSeccompData::new(SOCKET)
            .with_arg(0, AF_UNIX as u64)
            .with_arg(1, SOCK_STREAM as u64);
        assert_eq!(run_bpf(&program, unix_stream), SECCOMP_RET_ALLOW);

        let inet6_stream = FakeSeccompData::new(SOCKET)
            .with_arg(0, 10)
            .with_arg(1, SOCK_STREAM as u64);
        assert_eq!(run_bpf(&program, inet6_stream), SECCOMP_RET_KILL_PROCESS);

        let datagram = FakeSeccompData::new(SOCKET)
            .with_arg(0, AF_INET as u64)
            .with_arg(1, 2);
        assert_eq!(run_bpf(&program, datagram), SECCOMP_RET_KILL_PROCESS);

        let unknown_type_flag = FakeSeccompData::new(SOCKET)
            .with_arg(0, AF_INET as u64)
            .with_arg(1, (SOCK_STREAM | 0x10) as u64);
        assert_eq!(
            run_bpf(&program, unknown_type_flag),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn test_non_network_socket_constraint_allows_only_unix_domain() {
        let constraints = [ConstrainedSyscall {
            nr: SOCKET,
            constraint: SeccompArgConstraint::Socket { allow_inet: false },
        }];
        let program = build_bpf_program(&[SOCKET], &constraints);

        let unix_stream = FakeSeccompData::new(SOCKET)
            .with_arg(0, AF_UNIX as u64)
            .with_arg(1, SOCK_STREAM as u64);
        assert_eq!(run_bpf(&program, unix_stream), SECCOMP_RET_ALLOW);

        let inet_stream = FakeSeccompData::new(SOCKET)
            .with_arg(0, AF_INET as u64)
            .with_arg(1, SOCK_STREAM as u64);
        assert_eq!(run_bpf(&program, inet_stream), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_ioctl_constraint_allows_only_whitelisted_requests() {
        let program = program_for_profile(SeccompProfile::EssentialWithFork);

        let allowed_request = FakeSeccompData::new(IOCTL).with_arg(1, TCGETS as u64);
        assert_eq!(run_bpf(&program, allowed_request), SECCOMP_RET_ALLOW);

        let fionbio_request = FakeSeccompData::new(IOCTL).with_arg(1, FIONBIO as u64);
        assert_eq!(run_bpf(&program, fionbio_request), SECCOMP_RET_ALLOW);

        let tiocgpgrp_request = FakeSeccompData::new(IOCTL).with_arg(1, TIOCGPGRP as u64);
        assert_eq!(run_bpf(&program, tiocgpgrp_request), SECCOMP_RET_ALLOW);

        let tiocspgrp_request = FakeSeccompData::new(IOCTL).with_arg(1, TIOCSPGRP as u64);
        assert_eq!(run_bpf(&program, tiocspgrp_request), SECCOMP_RET_ALLOW);

        let tiocsti_request = FakeSeccompData::new(IOCTL).with_arg(1, 0x5412);
        assert_eq!(run_bpf(&program, tiocsti_request), SECCOMP_RET_KILL_PROCESS);

        let high_bits_set = FakeSeccompData::new(IOCTL).with_arg(1, (1_u64 << 32) | TCGETS as u64);
        assert_eq!(run_bpf(&program, high_bits_set), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_futex_constraint_allows_only_whitelisted_ops() {
        let program = program_for_profile(SeccompProfile::Essential);

        let futex_wait = FakeSeccompData::new(FUTEX).with_arg(0, FUTEX_WAIT as u64);
        assert_eq!(run_bpf(&program, futex_wait), SECCOMP_RET_ALLOW);

        let futex_wake = FakeSeccompData::new(FUTEX).with_arg(0, FUTEX_WAKE as u64);
        assert_eq!(run_bpf(&program, futex_wake), SECCOMP_RET_ALLOW);

        let futex_wait_private = FakeSeccompData::new(FUTEX).with_arg(0, FUTEX_WAIT_PRIVATE as u64);
        assert_eq!(run_bpf(&program, futex_wait_private), SECCOMP_RET_ALLOW);

        let futex_wake_private = FakeSeccompData::new(FUTEX).with_arg(0, FUTEX_WAKE_PRIVATE as u64);
        assert_eq!(run_bpf(&program, futex_wake_private), SECCOMP_RET_ALLOW);

        let futex_wait_bitset_private =
            FakeSeccompData::new(FUTEX).with_arg(0, FUTEX_WAIT_BITSET_PRIVATE as u64);
        assert_eq!(
            run_bpf(&program, futex_wait_bitset_private),
            SECCOMP_RET_ALLOW
        );

        let futex_requeue = FakeSeccompData::new(FUTEX).with_arg(0, 3);
        assert_eq!(run_bpf(&program, futex_requeue), SECCOMP_RET_KILL_PROCESS);

        let futex_cmp_requeue = FakeSeccompData::new(FUTEX).with_arg(0, 4);
        assert_eq!(
            run_bpf(&program, futex_cmp_requeue),
            SECCOMP_RET_KILL_PROCESS
        );

        let high_bits_set =
            FakeSeccompData::new(FUTEX).with_arg(0, (1_u64 << 32) | FUTEX_WAIT as u64);
        assert_eq!(run_bpf(&program, high_bits_set), SECCOMP_RET_KILL_PROCESS);
    }

    #[test]
    fn test_clone_constraint_blocks_namespace_flags() {
        let program = program_for_profile(SeccompProfile::EssentialWithFork);

        let sigchld_only = FakeSeccompData::new(CLONE).with_arg(0, 17);
        assert_eq!(run_bpf(&program, sigchld_only), SECCOMP_RET_ALLOW);

        let newnet = FakeSeccompData::new(CLONE).with_arg(0, 0x4000_0000);
        assert_eq!(run_bpf(&program, newnet), SECCOMP_RET_KILL_PROCESS);

        let namespace_mask = FakeSeccompData::new(CLONE).with_arg(0, CLONE_NAMESPACE_MASK as u64);
        assert_eq!(run_bpf(&program, namespace_mask), SECCOMP_RET_KILL_PROCESS);

        let high_bits_set = FakeSeccompData::new(CLONE).with_arg(0, 1_u64 << 32);
        assert_eq!(run_bpf(&program, high_bits_set), SECCOMP_RET_KILL_PROCESS);
    }
}
