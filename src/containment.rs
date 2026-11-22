//! Pin namespace membership and constrain IPC for deployed workloads.
//!
//! This narrow seccomp policy prevents a confined child from obtaining a new
//! user namespace and then changing clocks, mounts or network membership after
//! IPC attestation. Production workloads additionally use only the connected
//! endpoints delivered by the deployer. Both filters are inherited across exec.
//! Ordinary fork/clone threads remain available under their cgroup task limit.
//! clone3 cannot be safely inspected by classic BPF (its flags are indirect), so
//! ENOSYS selects libc's legacy clone fallback. Unsupported kernels fail closed.
use std::io;

#[cfg(target_arch = "x86_64")]
const ARCH: u32 = 0xc000003e;
#[cfg(target_arch = "x86")]
const ARCH: u32 = 0x40000003;
#[cfg(target_arch = "aarch64")]
const ARCH: u32 = 0xc00000b7;
#[cfg(target_arch = "arm")]
const ARCH: u32 = 0x40000028;

const LOAD: u16 = 0x20;
const EQUAL: u16 = 0x15;
const BITS: u16 = 0x45;
const RETURN: u16 = 0x06;
const ALLOW: u32 = 0x7fff0000;
const KILL: u32 = 0x80000000;
const ERRNO: u32 = 0x00050000;
const NAMESPACES: u32 = 0x7e020080;
const fn stmt(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}
const fn jump(code: u16, value: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: yes,
        jf: no,
        k: value,
    }
}
fn program() -> [libc::sock_filter; 16] {
    [
        stmt(LOAD, 4),
        jump(EQUAL, ARCH, 1, 0),
        stmt(RETURN, KILL),
        stmt(LOAD, 0),
        // x32 shares the x86_64 audit architecture. Never interpret its syscall
        // numbers using the native table. This bit is invalid on the other ABIs.
        jump(BITS, 0x40000000, 10, 0),
        jump(EQUAL, libc::SYS_unshare as u32, 8, 0),
        jump(EQUAL, libc::SYS_setns as u32, 7, 0),
        jump(EQUAL, libc::SYS_clone3 as u32, 5, 0),
        jump(EQUAL, libc::SYS_clone as u32, 1, 0),
        stmt(RETURN, ALLOW),
        stmt(LOAD, 16),
        jump(BITS, NAMESPACES, 2, 0),
        stmt(RETURN, ALLOW),
        stmt(RETURN, ERRNO | libc::ENOSYS as u32),
        stmt(RETURN, ERRNO | libc::EPERM as u32),
        stmt(RETURN, KILL),
    ]
}

/// Install after namespace placement and credential drop, before exec. All work
/// uses a fixed stack buffer; this is suitable for Command::pre_exec. A child
/// may add stricter filters but cannot remove this policy. NNP must already be on.
pub fn pin_namespaces() -> io::Result<()> {
    let mut code = program();
    install(&mut code)
}

fn install(code: &mut [libc::sock_filter]) -> io::Result<()> {
    let filter = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    if unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &filter) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// Each production process has its own net/IPC/mount namespaces and host IDs.
// Deny creation or adoption of further socket endpoints, including io_uring
// requests, and deny APIs for copying another process's state or handles.
// The authenticated transport still needs peer credentials, pidfd_open, poll,
// sendmsg and recvmsg. The bootstrap carrier is already connected at exec.
const DENIED: &[libc::c_long] = &[
    libc::SYS_socket, libc::SYS_socketpair, libc::SYS_connect, libc::SYS_bind,
    libc::SYS_listen, libc::SYS_accept4,
    #[cfg(not(target_arch = "x86"))]
    libc::SYS_accept,
    libc::SYS_io_uring_setup, libc::SYS_io_uring_enter, libc::SYS_io_uring_register,
    libc::SYS_ptrace, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
    libc::SYS_pidfd_getfd, libc::SYS_perf_event_open,
    libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key,
    libc::SYS_inotify_init1, libc::SYS_inotify_add_watch,
    #[cfg(not(target_arch = "aarch64"))]
    libc::SYS_inotify_init,
    libc::SYS_fanotify_init, libc::SYS_fanotify_mark,
    libc::SYS_mq_open, libc::SYS_mknodat,
    #[cfg(not(target_arch = "aarch64"))]
    libc::SYS_mknod,
    #[cfg(not(target_arch = "x86"))]
    libc::SYS_shmget,
    #[cfg(not(target_arch = "x86"))]
    libc::SYS_semget,
    #[cfg(not(target_arch = "x86"))]
    libc::SYS_msgget,
    // i386 exposes both the legacy ipc multiplexer and the direct Linux 5.1
    // semget, shmget and msgget entries. libc lacks names for the latter.
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    117,
    #[cfg(target_arch = "x86")]
    393,
    #[cfg(target_arch = "x86")]
    395,
    #[cfg(target_arch = "x86")]
    399,
    // A VM may update records under its 0700 rollback root. Its credentials
    // cannot make that directory accessible to a peer by changing mode or ACL.
    #[cfg(not(target_arch = "aarch64"))]
    libc::SYS_chmod,
    libc::SYS_fchmod, libc::SYS_fchmodat, 452, // fchmodat2 on all supported ABIs
    libc::SYS_setxattr, libc::SYS_lsetxattr, libc::SYS_fsetxattr, 463, // setxattrat
];

fn endpoint_program() -> [libc::sock_filter; DENIED.len() + 3] {
    let mut code = [stmt(RETURN, ALLOW); DENIED.len() + 3];
    code[0] = stmt(LOAD, 0);
    for (index, &call) in DENIED.iter().enumerate() {
        code[index + 1] = jump(EQUAL, call as u32, (DENIED.len() - index) as u8, 0);
    }
    code[DENIED.len() + 2] = stmt(RETURN, ERRNO | libc::EPERM as u32);
    code
}

// i386 multiplexes socket calls and legacy ARM uses the same entry number.
// Only operations on an already connected endpoint are needed by a workload.
#[cfg(any(target_arch = "x86", target_arch = "arm", test))]
fn socketcall_program() -> [libc::sock_filter; 19] {
    const SOCKETCALL: u32 = 102;
    const EXISTING: [u32; 13] = [6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 20];
    let mut code = [stmt(RETURN, ALLOW); 19];
    code[0] = stmt(LOAD, 0);
    code[1] = jump(EQUAL, SOCKETCALL, 1, 0);
    code[3] = stmt(LOAD, 16);
    for (index, call) in EXISTING.iter().enumerate() {
        code[index + 4] = jump(EQUAL, *call, (EXISTING.len() - index) as u8, 0);
    }
    code[17] = stmt(RETURN, ERRNO | libc::EPERM as u32);
    code
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Role {
    Vm,
    NativeDriver,
}

// A read-only bind still shares the underlying inodes. Native providers have
// no file-lock protocol. The trusted VM needs flock for its private WSEA
// rollback files. Neither role receives filesystem notification authority.
const DRIVER_FCNTL: &[libc::c_int] = &[
    libc::F_GETFD, libc::F_SETFD, libc::F_GETFL, libc::F_SETFL,
    libc::F_DUPFD, libc::F_DUPFD_CLOEXEC, libc::F_GETPIPE_SZ, libc::F_SETPIPE_SZ,
    libc::F_GET_SEALS, libc::F_ADD_SEALS,
];

#[cfg(any(target_arch = "x86", target_arch = "arm"))]
const FCNTL64: libc::c_long = libc::SYS_fcntl64;
#[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
const FCNTL64: libc::c_long = libc::SYS_fcntl;

fn file_program(role: Role) -> [libc::sock_filter; DRIVER_FCNTL.len() + 11] {
    const DENY: u32 = ERRNO | libc::EPERM as u32;
    let unlisted = if role == Role::NativeDriver { DENY } else { ALLOW };
    let mut code = [stmt(RETURN, ALLOW); DRIVER_FCNTL.len() + 11];
    code[0] = stmt(LOAD, 0);
    code[1] = jump(EQUAL, libc::SYS_flock as u32, 0, 1);
    code[2] = stmt(RETURN, unlisted);
    code[3] = jump(EQUAL, libc::SYS_fcntl as u32, 2, 0);
    code[4] = jump(EQUAL, FCNTL64 as u32, 1, 0);
    code[6] = stmt(LOAD, 24); // low word of the second syscall argument
    code[7] = jump(EQUAL, libc::F_NOTIFY as u32, 0, 1);
    code[8] = stmt(RETURN, DENY);
    for (index, &command) in DRIVER_FCNTL.iter().enumerate() {
        code[9 + index] = jump(EQUAL, command as u32, (DRIVER_FCNTL.len() - index) as u8, 0);
    }
    code[9 + DRIVER_FCNTL.len()] = stmt(RETURN, unlisted);
    code
}

/// Apply from the production child's pre-exec hook after arranging its closed
/// descriptor set. The namespace filter also rejects alternate syscall ABIs.
pub(crate) fn restrict_workload(role: Role) -> io::Result<()> {
    pin_namespaces()?;
    install(&mut endpoint_program())?;
    install(&mut file_program(role))?;
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    install(&mut socketcall_program())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn eval(code: &[libc::sock_filter], arch: u32, syscall: u32, args: [u32; 2]) -> u32 {
        let mut acc = 0;
        let mut pc = 0;
        loop {
            let ins = code[pc];
            match ins.code {
                LOAD => {
                    acc = match ins.k {
                        4 => arch,
                        0 => syscall,
                        16 => args[0],
                        24 => args[1],
                        _ => panic!("offset"),
                    }
                }
                EQUAL | BITS => {
                    let yes = if ins.code == EQUAL {
                        acc == ins.k
                    } else {
                        acc & ins.k != 0
                    };
                    pc += if yes { ins.jt } else { ins.jf } as usize;
                }
                RETURN => return ins.k,
                _ => panic!("instruction"),
            }
            pc += 1;
        }
    }
    fn evaluate(arch: u32, syscall: u32, flags: u32) -> u32 {
        eval(&program(), arch, syscall, [flags, 0])
    }

    #[test]
    fn only_preconnected_transports_remain_available() {
        for &call in DENIED {
            assert_eq!(eval(&endpoint_program(), ARCH, call as u32, [0; 2]), ERRNO | libc::EPERM as u32);
        }
        for call in [libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_getsockopt, libc::SYS_pidfd_open] {
            assert_eq!(eval(&endpoint_program(), ARCH, call as u32, [0; 2]), ALLOW);
        }
        for role in [Role::Vm, Role::NativeDriver] {
            let files = file_program(role);
            let denied = ERRNO | libc::EPERM as u32;
            let lock = if role == Role::Vm { ALLOW } else { denied };
            assert_eq!(eval(&files, ARCH, libc::SYS_flock as u32, [0; 2]), lock);
            for syscall in [libc::SYS_fcntl, FCNTL64] {
                assert_eq!(eval(&files, ARCH, syscall as u32, [31, libc::F_GETFD as u32]), ALLOW);
                assert_eq!(eval(&files, ARCH, syscall as u32, [31, libc::F_NOTIFY as u32]), denied);
                assert_eq!(eval(&files, ARCH, syscall as u32, [31, libc::F_SETLK as u32]), lock);
            }
        }
        for operation in 0..=21 {
            let allowed = matches!(operation, 6 | 7 | 9..=17 | 19 | 20);
            assert_eq!(eval(&socketcall_program(), ARCH, 102, [operation, 0]) == ALLOW, allowed);
        }
        assert_eq!(eval(&socketcall_program(), ARCH, libc::SYS_read as u32, [0; 2]), ALLOW);
    }

    // The cross-ABI suite runs Arm under qemu-user, which cannot install a
    // guest kernel filter. Exercise the real filter on the native Linux ABIs.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    #[test]
    fn child_filter_preserves_inherited_business_socket() {
        use std::io::Read;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let _lock = crate::FORK_AND_LOCK_TEST.lock().unwrap();
        let (mut parent, child) = UnixStream::pair().unwrap();
        let fd = child.as_raw_fd();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                let mut peer: libc::ucred = std::mem::zeroed();
                let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
                let ok = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                    && restrict_workload(Role::NativeDriver).is_ok()
                    && libc::fcntl(fd, libc::F_GETFD) >= 0
                    && libc::fcntl(fd, libc::F_NOTIFY, 0) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                    && libc::flock(-1, libc::LOCK_SH) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                    && libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut peer as *mut libc::ucred).cast(), &mut size) == 0
                    && peer.pid == libc::getppid()
                    && libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
                    && libc::send(fd, b"A".as_ptr().cast(), 1, libc::MSG_NOSIGNAL) == 1;
                libc::_exit(if ok { 0 } else { 1 });
            }
        }
        drop(child);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(status, 0);
        let mut data = [0];
        parent.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"A");
    }
    #[test]
    fn namespace_pinning_preserves_plain_threads_and_denies_abi_aliases() {
        assert_eq!(evaluate(ARCH ^ 1, libc::SYS_read as u32, 0), KILL);
        assert_eq!(evaluate(ARCH, 0x40000000, 0), KILL);
        assert_eq!(
            evaluate(ARCH, libc::SYS_unshare as u32, 0),
            ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            evaluate(ARCH, libc::SYS_setns as u32, 0),
            ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            evaluate(ARCH, libc::SYS_clone3 as u32, 0),
            ERRNO | libc::ENOSYS as u32
        );
        for flag in [
            0x80, 0x20000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
        ] {
            assert_eq!(
                evaluate(ARCH, libc::SYS_clone as u32, flag),
                ERRNO | libc::EPERM as u32
            );
        }
        assert_eq!(
            evaluate(ARCH, libc::SYS_clone as u32, libc::SIGCHLD as u32),
            ALLOW
        );
        assert_eq!(evaluate(ARCH, libc::SYS_clone as u32, 0x003d0f00), ALLOW);
        assert_eq!(evaluate(ARCH, libc::SYS_read as u32, u32::MAX), ALLOW);
    }
}
