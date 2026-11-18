//! Pin the namespace membership established by the trusted provisioner.
//!
//! This narrow seccomp policy prevents a confined child from obtaining a new
//! user namespace and then changing clocks, mounts or network membership after
//! IPC attestation. It does not claim to be a general native-driver sandbox.
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
    let filter = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    if unsafe { libc::syscall(libc::SYS_seccomp, 1, 0, &filter) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evaluate(arch: u32, syscall: u32, flags: u32) -> u32 {
        let mut acc = 0;
        let code = program();
        let mut pc = 0;
        loop {
            let ins = code[pc];
            match ins.code {
                LOAD => {
                    acc = match ins.k {
                        4 => arch,
                        0 => syscall,
                        16 => flags,
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
