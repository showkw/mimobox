//! Seccomp-bpf system call filtering.
//!
//! Implements BPF-based allowlist system call filtering, applied after `fork` and before `exec`.
//! Provides two profiles:
//! - Essential: allows only about 40 core system calls.
//! - Network: Essential plus network-related system calls.

use mimobox_core::{SandboxError, SeccompProfile};

// BPF 指令结构体（对应 Linux sock_filter）
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
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp 返回值
// IMPORTANT-01 修复：使用 KILL_PROCESS 替代 KILL_THREAD，确保整个进程树被终止
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;

// seccomp_data 偏移量
const SECCOMP_DATA_NR: u32 = 0; // offsetof(struct seccomp_data, nr)

// prctl 常量
const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: i32 = 2;

// x86_64 系统调用号（保留全部定义供参考，未使用的允许 dead_code）
#[allow(dead_code, missing_docs)]
mod syscall_nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const OPEN: u32 = 2;
    pub const CLOSE: u32 = 3;
    pub const STAT: u32 = 4;
    pub const FSTAT: u32 = 5;
    pub const LSTAT: u32 = 6;
    pub const POLL: u32 = 7;
    pub const MMAP: u32 = 9;
    pub const MPROTECT: u32 = 10;
    pub const MUNMAP: u32 = 11;
    pub const BRK: u32 = 12;
    pub const RT_SIGACTION: u32 = 13;
    pub const RT_SIGPROCMASK: u32 = 14;
    pub const RT_SIGRETURN: u32 = 15;
    pub const IOCTL: u32 = 16;
    pub const PREAD64: u32 = 17;
    pub const PWRITE64: u32 = 18;
    pub const READV: u32 = 19;
    pub const WRITEV: u32 = 20;
    pub const ACCESS: u32 = 21;
    pub const PIPE: u32 = 22;
    pub const SELECT: u32 = 23;
    pub const SCHED_YIELD: u32 = 24;
    pub const MREMAP: u32 = 25;
    pub const NANOSLEEP: u32 = 35;
    pub const ALARM: u32 = 37;
    pub const GETPID: u32 = 39;
    pub const SENDFILE: u32 = 40;
    pub const SOCKET: u32 = 41;
    pub const CONNECT: u32 = 42;
    pub const ACCEPT: u32 = 43;
    pub const SENDTO: u32 = 44;
    pub const RECVFROM: u32 = 45;
    pub const SENDMSG: u32 = 46;
    pub const RECVMSG: u32 = 47;
    pub const SHUTDOWN: u32 = 48;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const GETSOCKNAME: u32 = 51;
    pub const GETPEERNAME: u32 = 52;
    pub const SETSOCKOPT: u32 = 54;
    pub const GETSOCKOPT: u32 = 55;
    pub const CLONE: u32 = 56;
    pub const FORK: u32 = 57;
    pub const VFORK: u32 = 58;
    pub const EXECVE: u32 = 59;
    pub const EXIT: u32 = 60;
    pub const WAIT4: u32 = 61;
    pub const UNAME: u32 = 63;
    pub const FCNTL: u32 = 72;
    pub const FSYNC: u32 = 74;
    pub const FTRUNCATE: u32 = 77;
    pub const GETDENTS: u32 = 78;
    pub const GETCWD: u32 = 79;
    pub const CHDIR: u32 = 80;
    pub const RENAME: u32 = 82;
    pub const MKDIR: u32 = 83;
    pub const UNLINK: u32 = 87;
    pub const SYMLINK: u32 = 88;
    pub const READLINK: u32 = 89;
    pub const CHMOD: u32 = 90;
    pub const GETUID: u32 = 102;
    pub const SYSLOG: u32 = 103;
    pub const GETGID: u32 = 104;
    pub const SETUID: u32 = 105;
    pub const SETGID: u32 = 106;
    pub const GETEUID: u32 = 107;
    pub const GETEGID: u32 = 108;
    pub const SETPGID: u32 = 109;
    pub const GETPPID: u32 = 110;
    pub const GETPGRP: u32 = 111;
    pub const SETSID: u32 = 112;
    pub const GETGROUPS: u32 = 115;
    pub const SETGROUPS: u32 = 116;
    pub const SIGALTSTACK: u32 = 131;
    pub const RT_SIGQUEUEINFO: u32 = 129;
    pub const RT_TGSIGQUEUEINFO: u32 = 240;
    pub const MADVISE: u32 = 28;
    pub const DUP: u32 = 32;
    pub const DUP2: u32 = 33;
    pub const PAUSE: u32 = 34;
    pub const ARCH_PRCTL: u32 = 158;
    pub const SET_TID_ADDRESS: u32 = 218;
    pub const EXIT_GROUP: u32 = 231;
    pub const SET_ROBUST_LIST: u32 = 273;
    pub const GET_ROBUST_LIST: u32 = 274;
    pub const PRLIMIT64: u32 = 302;
    pub const GETRANDOM: u32 = 318;
    pub const STATFS: u32 = 137;
    pub const PRCTL: u32 = 157;
    pub const GETDENTS64: u32 = 217;
    pub const RSEQ: u32 = 334;
    pub const PREADV: u32 = 296;
    pub const PWRITEV: u32 = 297;
    pub const FUTEX: u32 = 202;
    pub const CLOCK_GETTIME: u32 = 228;
    pub const CLOCK_GETRES: u32 = 229;
    pub const CLOCK_NANOSLEEP: u32 = 230;
    pub const TGKILL: u32 = 234;
    pub const TEE: u32 = 276;
    pub const SPLICE: u32 = 275;
    pub const EPOLL_CREATE: u32 = 213;
    pub const EPOLL_WAIT: u32 = 232;
    pub const EPOLL_CTL: u32 = 233;
    pub const EPOLL_CREATE1: u32 = 291;
    pub const EPOLL_PWAIT: u32 = 281;
    pub const TIMERFD_CREATE: u32 = 283;
    pub const TIMERFD_SETTIME: u32 = 286;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const UNLINKAT: u32 = 263;
    pub const READLINKAT: u32 = 267;
    pub const FSTATAT: u32 = 262;
    pub const FACCESSAT: u32 = 269;
    pub const NEWFSTATAT: u32 = 262;
    pub const FCHMODAT: u32 = 268;
    pub const LINKAT: u32 = 265;
    pub const SYMLINKAT: u32 = 266;
    pub const RENAMEAT: u32 = 264;
    pub const FUTIMENSAT: u32 = 280;
    pub const PPOLL: u32 = 271;
    pub const LSEEK: u32 = 8;
    pub const SIGPROCMASK: u32 = 14;
    pub const SIGPENDING: u32 = 73;
    pub const KILL: u32 = 62;
    pub const TKILL: u32 = 200;
    pub const SIGTIMEDWAIT: u32 = 128;
    pub const SIGWAITINFO: u32 = 130;
    pub const PIPE2: u32 = 293;
    pub const DUP3: u32 = 292;
    pub const GETTID: u32 = 186;
    pub const GETRLIMIT: u32 = 97;
    pub const UMASK: u32 = 95;
    pub const STATX: u32 = 332;
    pub const FADVISE64: u32 = 221;
    pub const CLONE3: u32 = 435;
    pub const CLOSE_RANGE: u32 = 436;
    pub const OPENAT2: u32 = 437;
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
        FCNTL,
        FSYNC,
        FTRUNCATE,
        FUTIMENSAT,
        MKDIR,
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
    ]
}

/// Builds the system call allowlist for `allow_fork` mode.
///
/// Adds process-creation system calls on top of Essential for workloads such as shells that fork
/// child processes. Also allows `ioctl` because shells need terminal ioctls such as `TCGETS`
/// during startup. Still excludes `setpgid`/`setsid` to prevent escaping the supervisor process
/// group, `kill`/`tkill` to prevent signaling other processes, `prctl` to prevent modifying
/// security attributes, and similar calls.
pub fn fork_allowed_syscalls() -> Vec<u32> {
    use syscall_nr::*;
    let mut syscalls = essential_syscalls();
    syscalls.extend_from_slice(&[
        CLONE,
        FORK,
        // shell 执行外部命令时可能经由 vfork/posix_spawn 进入子进程路径。
        VFORK,
        CLONE3,
        WAIT4,
        // shell 运行需要 ioctl（终端 TCGETS/TCSETS 等）
        IOCTL,
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

/// Generates a BPF system call allowlist filter.
///
/// BPF program structure, with `N + 3` instructions where `N = allowed.len()`:
///
/// ```text
/// [0]     BPF_LD:   Load seccomp_data.nr into accumulator A
/// [1]     BPF_JEQ:  If A == allowed[0], skip (N-0) instructions -> ALLOW
/// [2]     BPF_JEQ:  If A == allowed[1], skip (N-1) instructions -> ALLOW
/// ...
/// [i+1]   BPF_JEQ:  If A == allowed[i], skip (N-i) instructions -> ALLOW
/// ...
/// [N]     BPF_JEQ:  If A == allowed[N-1], skip 1 instruction -> ALLOW
/// [N+1]   BPF_RET:  SECCOMP_RET_KILL_PROCESS (does not match any allowlist entry)
/// [N+2]   BPF_RET:  SECCOMP_RET_ALLOW (allowlist hit)
/// ```
///
/// Jump offset calculation: for the `i`th JEQ (0-indexed), the following instructions remain:
///   - (N - i - 1) JEQ instructions + 1 KILL instruction
///   - jt = (N - i - 1) + 1 = N - i
fn build_bpf_program(allowed: &[u32]) -> Vec<SockFilter> {
    // FATAL-01 / IMPORTANT-07 修复：防御性断言，防止 BPF jt 偏移 u8 溢出
    // jt 最大 255，跳过指令数 = total_jeq - i，所以 total_jeq 最大 253（首条 jt=total_jeq ≤ 253）
    // 同时确保总指令数 N+3 ≤ u16::MAX
    assert!(
        allowed.len() <= 253,
        "BPF 白名单过长（最多 253 条），当前 {} 条",
        allowed.len()
    );

    let total_jeq = allowed.len();
    let mut prog = Vec::with_capacity(2 + total_jeq + 1);

    // [0] 加载系统调用号到累加器
    prog.push(SockFilter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    });

    // [1..N+1] JEQ 匹配链：对每个允许的系统调用号生成条件跳转
    for (i, &syscall_nr) in allowed.iter().enumerate() {
        let instructions_to_skip = (total_jeq - i) as u8;
        prog.push(SockFilter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: instructions_to_skip, // 匹配时跳过后续 JEQ + KILL，直达 ALLOW
            jf: 0,                    // 不匹配则继续下一条 JEQ
            k: syscall_nr,
        });
    }

    // [N+1] 默认动作：未命中白名单 → 终止进程
    prog.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // [N+2] ALLOW 目标：白名单命中 → 放行
    prog.push(SockFilter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

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

    let prog = build_bpf_program(&allowed);

    // 设置 PR_SET_NO_NEW_PRIVS，防止子进程提权绕过 seccomp
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
        let errno = unsafe { *libc::__errno_location() };
        return Err(SandboxError::SeccompFailed(format!(
            "prctl(PR_SET_SECCOMP) 失败: errno={errno}"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::essential_syscalls;
    use super::fork_allowed_syscalls;
    use super::syscall_nr::{RT_SIGQUEUEINFO, RT_TGSIGQUEUEINFO, SETPGID, SETSID, TGKILL};

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
}
