#![cfg(target_os = "linux")]

//! Host-side seccomp hardening for the microVM backend.

// BPF 指令结构体（对应 Linux sock_filter）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

// BPF 程序结构体（对应 Linux sock_fprog）。
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

const PR_SET_NO_NEW_PRIVS: i32 = 38;
const PR_SET_SECCOMP: i32 = 22;
const SECCOMP_MODE_FILTER: i32 = 2;

const SYS_PTRACE: u32 = 101;
const SYS_MOUNT: u32 = 40;
const SYS_UMOUNT2: u32 = 39;
const SYS_REBOOT: u32 = 169;
const SYS_KEXEC_LOAD: u32 = 104;
const SYS_KEXEC_FILE_LOAD: u32 = 320;
const SYS_SWAPOFF: u32 = 168;
const SYS_SWAPON: u32 = 167;
const SYS_PERF_EVENT_OPEN: u32 = 298;
const SYS_BPF: u32 = 321;
const SYS_KEYCTL: u32 = 250;
const SYS_ADD_KEY: u32 = 248;
const SYS_REQUEST_KEY: u32 = 249;

const BLOCKED_SYSCALLS: &[u32] = &[
    SYS_PTRACE,
    SYS_MOUNT,
    SYS_UMOUNT2,
    SYS_REBOOT,
    SYS_KEXEC_LOAD,
    SYS_KEXEC_FILE_LOAD,
    SYS_SWAPOFF,
    SYS_SWAPON,
    SYS_PERF_EVENT_OPEN,
    SYS_BPF,
    SYS_KEYCTL,
    SYS_ADD_KEY,
    SYS_REQUEST_KEY,
];

const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

const fn load_arch() -> SockFilter {
    bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH)
}

const fn load_nr() -> SockFilter {
    bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR)
}

const fn ret_allow() -> SockFilter {
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
}

const fn ret_errno(errno: u32) -> SockFilter {
    bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | errno)
}

const fn jeq_arch(arch: u32, jt: u8, jf: u8) -> SockFilter {
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, arch, jt, jf)
}

const fn jeq_nr(nr: u32, jt: u8, jf: u8) -> SockFilter {
    bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jt, jf)
}

fn build_filter() -> Vec<SockFilter> {
    let mut filter = Vec::with_capacity(4 + BLOCKED_SYSCALLS.len() * 2);

    filter.push(load_arch());
    filter.push(jeq_arch(AUDIT_ARCH_X86_64, 1, 0));
    filter.push(ret_allow());
    filter.push(load_nr());

    for &syscall_nr in BLOCKED_SYSCALLS {
        filter.push(jeq_nr(syscall_nr, 0, 1));
        filter.push(ret_errno(libc::EPERM as u32));
    }

    filter.push(ret_allow());
    filter
}

/// Applies the host-side seccomp blacklist used by KVM microVM processes.
pub fn apply_host_seccomp() -> Result<(), mimobox_core::SandboxError> {
    let filter = build_filter();
    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    // SAFETY: PR_SET_NO_NEW_PRIVS=38 设置为 1，防止子进程获取更多权限。
    // 参数正确，返回值必须为 0。
    let ret = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(mimobox_core::SandboxError::SeccompFailed(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: PR_SET_SECCOMP=22 设置 SECCOMP_MODE_FILTER=2，应用 BPF 过滤器。
    // prog 指向有效 SockFprog；filter 在调用期间有效，内核会复制 BPF 程序。
    let ret = unsafe {
        libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const SockFprog as libc::c_ulong,
            0,
            0,
        )
    };
    if ret != 0 {
        return Err(mimobox_core::SandboxError::SeccompFailed(format!(
            "prctl(PR_SET_SECCOMP) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}
