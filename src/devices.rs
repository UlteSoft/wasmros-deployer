//! Exact Linux device-node policy for deployment-owned cgroup v2 children.
//!
//! Device discovery uses O_PATH, never an open that could activate hardware.
//! A fixed, bounded, helper-free BPF program permits only reviewed read/write
//! opens for exact (type, major, minor) identities. It never permits mknod.
//! The kernel retains the attachment after this manager dies or closes its FD;
//! only removal of the drained cgroup ends its lifetime. No detach API exists.
//!
//! This is an open/mknod boundary, NOT an ioctl, existing-FD, physical-serial,
//! protocol, network, or independent hardware-stop boundary. The provisioner
//! must close unapproved inherited FDs, isolate credentials/namespaces, and use
//! a trusted receiver for command semantics. Root and the kernel remain trusted.
use crate::manifest::Result;
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const MAX_RULES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Block = 1,
    Character = 2,
}

/// A kernel device number is independent of its pathname aliases. It does not
/// identify a physical serial number across unplug/replug or an OS reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub kind: Kind,
    pub major: u32,
    pub minor: u32,
}
impl Key {
    pub(crate) fn claim_name(self) -> String {
        format!("device-{}-{}-{}", self.kind as u8, self.major, self.minor)
    }
}

/// Pinned root-owned device inode; this descriptor has no read/write authority.
pub struct Device {
    descriptor: File,
    path: PathBuf,
    key: Key,
}
fn protected_directory(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("device path ancestors must be protected root-owned directories".into());
    }
    Ok(())
}
impl Device {
    /// Inspect an exact /dev path without following symlinks or opening hardware.
    /// Resolve by-id aliases in the trusted platform provisioner, then submit the
    /// canonical node. Every ancestor is pinned and checked before descending.
    pub fn inspect(path: &Path) -> Result<Self> {
        let text = path.to_str().ok_or("device path is not UTF-8")?;
        if !text.starts_with("/dev/") || text.len() > 4096 {
            return Err("device path must be an exact bounded /dev path".into());
        }
        let parts: Vec<_> = text[1..].split('/').collect();
        if parts.len() > 32
            || parts
                .iter()
                .any(|p| p.is_empty() || *p == "." || *p == ".." || p.len() > 255)
        {
            return Err("invalid device path component".into());
        }
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|e| e.to_string())?;
        protected_directory(&directory)?;
        for (index, part) in parts.iter().enumerate() {
            let name = CString::new(*part).map_err(|e| e.to_string())?;
            let last = index + 1 == parts.len();
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | if last { 0 } else { libc::O_DIRECTORY },
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            directory = unsafe { File::from_raw_fd(fd) };
            if !last {
                protected_directory(&directory)?;
            }
        }
        let m = directory.metadata().map_err(|e| e.to_string())?;
        let kind = if m.file_type().is_char_device() {
            Kind::Character
        } else if m.file_type().is_block_device() {
            Kind::Block
        } else {
            return Err("expected an actual character or block device, not an alias".into());
        };
        if m.uid() != 0 || m.nlink() == 0 {
            return Err("device node must be owned by root and still linked".into());
        }
        Ok(Self {
            descriptor: directory,
            path: path.to_owned(),
            key: Key {
                kind,
                major: libc::major(m.rdev()),
                minor: libc::minor(m.rdev()),
            },
        })
    }
    pub fn key(&self) -> Key {
        self.key
    }
    /// Recheck the reviewed inode immediately before admission. Replacing a
    /// node, including with another node with the same device number, fails.
    /// Hotplug may reuse a number without changing that inode: the trusted
    /// platform must independently confirm physical identity and safe state.
    pub fn revalidate(&self) -> Result<()> {
        let current = Self::inspect(&self.path)?;
        let a = self.descriptor.metadata().map_err(|e| e.to_string())?;
        let b = current.descriptor.metadata().map_err(|e| e.to_string())?;
        if current.key != self.key
            || a.dev() != b.dev()
            || a.ino() != b.ino()
            || a.nlink() == 0
            || a.mode() != b.mode()
        {
            return Err("reviewed device node changed; new human review required".into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read = 2,
    Write = 4,
    ReadWrite = 6,
}
#[derive(Clone, Copy, Debug)]
pub struct Rule {
    pub key: Key,
    pub access: Access,
}

/// No wildcards, mknod, raw bytecode, helpers, maps or mutable policy. Combining
/// independently reviewed read and write rights must be explicit ReadWrite.
pub struct Policy {
    rules: Vec<Rule>,
}
impl Policy {
    pub fn new(rules: &[Rule]) -> Result<Self> {
        if rules.len() > MAX_RULES {
            return Err("device rule budget exceeded".into());
        }
        let mut seen = BTreeSet::new();
        if rules.iter().any(|r| !seen.insert(r.key)) {
            return Err("duplicate device identity; review combined access explicitly".into());
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(rules.len())
            .map_err(|e| e.to_string())?;
        owned.extend_from_slice(rules);
        Ok(Self { rules: owned })
    }
    /// Host runtime baseline, not a grant of guest WASIp1 imports or paths.
    /// Physical devices, consoles, terminals, disks and mknod remain denied.
    pub fn vm() -> Self {
        Self {
            rules: vec![
                Rule {
                    key: Key {
                        kind: Kind::Character,
                        major: 1,
                        minor: 3,
                    },
                    access: Access::ReadWrite,
                },
                Rule {
                    key: Key {
                        kind: Kind::Character,
                        major: 1,
                        minor: 5,
                    },
                    access: Access::Read,
                },
                Rule {
                    key: Key {
                        kind: Kind::Character,
                        major: 1,
                        minor: 8,
                    },
                    access: Access::Read,
                },
                Rule {
                    key: Key {
                        kind: Kind::Character,
                        major: 1,
                        minor: 9,
                    },
                    access: Access::Read,
                },
            ],
        }
    }
    fn instructions(&self) -> Result<Vec<Instruction>> {
        let mut p = Vec::new();
        p.try_reserve_exact(9 + 8 * self.rules.len())
            .map_err(|e| e.to_string())?;
        // Context words: access/type, major, minor. All comparisons use JMP32,
        // including unsigned device numbers whose high bit might be set.
        p.extend([
            Instruction::new(0x61, 2, 1, 0, 0),     // r2 = ctx.access_type
            Instruction::new(0xbc, 3, 2, 0, 0),     // r3 = r2
            Instruction::new(0x74, 3, 0, 0, 16),    // r3 >>= 16
            Instruction::new(0x54, 2, 0, 0, 65535), // r2 &= 65535
            Instruction::new(0x61, 4, 1, 4, 0),
            Instruction::new(0x61, 5, 1, 8, 0),
            Instruction::new(0xb4, 0, 0, 0, 0), // default deny
            Instruction::new(0x16, 3, 0, (self.rules.len() * 8) as i16, 0),
        ]);
        for r in &self.rules {
            p.extend([
                Instruction::new(0x56, 2, 0, 7, r.key.kind as i32),
                Instruction::new(0x56, 4, 0, 6, r.key.major as i32),
                Instruction::new(0x56, 5, 0, 5, r.key.minor as i32),
                Instruction::new(0xbc, 6, 3, 0, 0),
                Instruction::new(0x54, 6, 0, 0, !(r.access as i32)),
                Instruction::new(0x56, 6, 0, 2, 0),
                Instruction::new(0xb4, 0, 0, 0, 1),
                Instruction::new(0x95, 0, 0, 0, 0),
            ]);
        }
        p.push(Instruction::new(0x95, 0, 0, 0, 0));
        Ok(p)
    }
    /// Attach only to a newly created, empty, protected cgroup v2 domain under
    /// the caller's exclusive provisioning ownership. Do not use this API on
    /// a concurrently administered cgroup. Existing programs are never replaced;
    /// ancestor restrictions stay effective. Failure forbids workload launch.
    pub fn attach_empty(&self, group: &File) -> Result<Installed> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("device filtering requires the privileged provisioner".into());
        }
        protected_directory(group)?;
        let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(group.as_raw_fd(), &mut fs) } != 0
            || fs.f_type as u64 != 0x63677270
        {
            return Err("device filter target must be a cgroup v2 directory".into());
        }
        if crate::cgroup::read(group, "cgroup.type")?.trim() != "domain"
            || !crate::cgroup::read(group, "cgroup.events")?
                .lines()
                .any(|l| l == "populated 0")
        {
            return Err("device filter requires an empty domain cgroup".into());
        }
        // Do not accidentally replace an existing single-attach program.
        let mut query = Query {
            target: group.as_raw_fd() as u32,
            attach_type: 6,
            query_flags: 0,
            attach_flags: 0,
            ids: 0,
            count: 0,
            pad: 0,
        };
        bpf(16, &mut query).map_err(|e| format!("device policy query failed: {e}"))?;
        if query.count != 0 || query.attach_flags != 0 {
            return Err("existing device policy cannot be replaced".into());
        }
        let code = self.instructions()?;
        let mut log = Vec::new();
        log.try_reserve_exact(65536).map_err(|e| e.to_string())?;
        log.resize(65536, 0u8);
        // No GPL-only helpers are used. This label makes no license grant for
        // the enclosing project, which is independently licensed by its owner.
        let mut load = Load {
            kind: 15,
            count: code.len() as u32,
            instructions: code.as_ptr() as usize as u64,
            license: c"Proprietary".as_ptr() as usize as u64,
            log_level: 1,
            log_size: log.len() as u32,
            log: log.as_mut_ptr() as usize as u64,
            kernel_version: 0,
            flags: 0,
            name: *b"wros_devices\0\0\0\0",
            ifindex: 0,
            attach_type: 6,
        };
        let fd = bpf(5, &mut load).map_err(|e| {
            let end = log.iter().position(|b| *b == 0).unwrap_or(log.len());
            format!(
                "device BPF load failed: {e}; {}",
                String::from_utf8_lossy(&log[..end])
            )
        })?;
        let program = unsafe { File::from_raw_fd(fd as i32) };
        let mut attach = Attach {
            target: group.as_raw_fd() as u32,
            program: fd as u32,
            attach_type: 6,
            flags: 0,
        };
        bpf(8, &mut attach).map_err(|e| format!("device BPF attachment failed: {e}"))?;
        Ok(Installed { _program: program })
    }
}

/// Closing this handle deliberately DOES NOT detach the kernel policy. A live
/// orphan must remain constrained until its supervisor drains/removes the group.
pub struct Installed {
    _program: File,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Instruction {
    code: u8,
    registers: u8,
    offset: i16,
    immediate: i32,
}
impl Instruction {
    fn new(code: u8, dst: u8, src: u8, offset: i16, immediate: i32) -> Self {
        let registers = if cfg!(target_endian = "little") {
            dst | (src << 4)
        } else {
            (dst << 4) | src
        };
        Self {
            code,
            registers,
            offset,
            immediate,
        }
    }
}
// Explicit padding and u64 pointer slots match __aligned_u64 on all five ABIs,
// including i686 and ARM32. Never send uninitialized padding to the kernel.
#[repr(C, align(8))]
struct Load {
    kind: u32,
    count: u32,
    instructions: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log: u64,
    kernel_version: u32,
    flags: u32,
    name: [u8; 16],
    ifindex: u32,
    attach_type: u32,
}
#[repr(C, align(8))]
struct Query {
    target: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    ids: u64,
    count: u32,
    pad: u32,
}
#[repr(C, align(8))]
struct Attach {
    target: u32,
    program: u32,
    attach_type: u32,
    flags: u32,
}
fn bpf<T>(command: u32, attribute: &mut T) -> std::io::Result<libc::c_long> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command,
            attribute as *mut T,
            std::mem::size_of::<T>(),
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Independent execution of the small generated instruction subset. Real
    // kernel verification and syscall enforcement are tested in disposable QEMU.
    fn evaluate(policy: &Policy, context: [u32; 3]) -> u32 {
        let code = policy.instructions().unwrap();
        let mut r = [0u32; 11];
        let mut pc = 0usize;
        for _ in 0..code.len() {
            let i = code[pc];
            let (dst, src) = if cfg!(target_endian = "little") {
                (i.registers & 15, i.registers >> 4)
            } else {
                (i.registers >> 4, i.registers & 15)
            };
            let (d, s) = (dst as usize, src as usize);
            match i.code {
                0x61 => {
                    assert_eq!(s, 1);
                    r[d] = context[i.offset as usize / 4];
                }
                0xbc => r[d] = r[s],
                0x74 => r[d] >>= i.immediate as u32,
                0x54 => r[d] &= i.immediate as u32,
                0xb4 => r[d] = i.immediate as u32,
                0x56 | 0x16 => {
                    if (r[d] == i.immediate as u32) == (i.code == 0x16) {
                        assert!(i.offset >= 0);
                        pc += i.offset as usize;
                    }
                }
                0x95 => return r[0],
                _ => panic!("unexpected instruction"),
            }
            pc += 1;
        }
        panic!("device program did not terminate");
    }
    #[test]
    fn bytecode_matches_exact_permission_semantics() {
        let rules = [
            Rule {
                key: Key {
                    kind: Kind::Character,
                    major: 1,
                    minor: 3,
                },
                access: Access::Read,
            },
            Rule {
                key: Key {
                    kind: Kind::Block,
                    major: 1,
                    minor: 3,
                },
                access: Access::Write,
            },
            Rule {
                key: Key {
                    kind: Kind::Character,
                    major: u32::MAX,
                    minor: u32::MAX,
                },
                access: Access::ReadWrite,
            },
        ];
        for rules in [&[][..], &rules[..], &Policy::vm().rules[..]] {
            let policy = Policy::new(rules).unwrap();
            for kind in [0, 1, 2, 3, 65535] {
                for major in [0, 1, 2, u32::MAX] {
                    for minor in [0, 3, 5, 8, 9, u32::MAX] {
                        for access in [0, 1, 2, 3, 4, 5, 6, 7, 8, 65535] {
                            let allowed = access != 0
                                && rules.iter().any(|r| {
                                    kind == r.key.kind as u32
                                        && major == r.key.major
                                        && minor == r.key.minor
                                        && access & !(r.access as u32) == 0
                                });
                            assert_eq!(
                                evaluate(&policy, [(access << 16) | kind, major, minor]),
                                u32::from(allowed)
                            );
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn limits_duplicates_and_cross_abi_layout() {
        assert_eq!(std::mem::size_of::<Instruction>(), 8);
        assert_eq!(std::mem::size_of::<Load>(), 72);
        assert_eq!(std::mem::offset_of!(Load, log), 32);
        assert_eq!(std::mem::offset_of!(Load, attach_type), 68);
        assert_eq!(std::mem::size_of::<Query>(), 32);
        assert_eq!(std::mem::size_of::<Attach>(), 16);
        let rules: Vec<_> = (0..128)
            .map(|minor| Rule {
                key: Key {
                    kind: Kind::Character,
                    major: 2,
                    minor,
                },
                access: Access::Write,
            })
            .collect();
        let policy = Policy::new(&rules).unwrap();
        assert_eq!(evaluate(&policy, [(4 << 16) | 2, 2, 127]), 1);
        assert_eq!(evaluate(&policy, [(2 << 16) | 2, 2, 127]), 0);
        assert!(Policy::new(&vec![rules[0]; 129]).is_err());
        assert!(Policy::new(&[rules[0], rules[0]]).is_err());
    }
    #[test]
    fn inspection_does_not_open_or_follow_device_aliases() {
        // qemu-user -L can redirect '/' into the user-owned cross sysroot.
        // That is not a trusted host device tree. Production must reject it;
        // the positive path is separately exercised under a full guest kernel.
        if protected_directory(&File::open("/").unwrap()).is_err() {
            assert!(Device::inspect(Path::new("/dev/null")).is_err());
            println!("untrusted emulated root rejected; positive device inspection requires the kernel fixture");
            return;
        }
        let node = Device::inspect(Path::new("/dev/null")).unwrap();
        node.revalidate().unwrap();
        let mut byte = 0u8;
        assert_eq!(
            unsafe {
                libc::read(
                    node.descriptor.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        for path in [
            "/dev/../dev/null",
            "/dev//null",
            "/dev/./null",
            "/dev/stdin",
            "/dev/",
            "/etc/passwd",
        ] {
            assert!(Device::inspect(Path::new(path)).is_err(), "{path}");
        }
    }
}
