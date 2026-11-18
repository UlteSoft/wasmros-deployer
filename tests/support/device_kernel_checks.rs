//! Destructive device-node fixtures run ONLY inside the disposable QEMU guest.
//! No hardware is used: nodes refer to Linux null/zero/full/random pseudo devices.
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use wros_deployer::devices::{Access, Device, Key, Kind, Policy, Rule};
use wros_deployer::ownership;

fn passed(name: &str) {
    println!("CASE {name} PASS");
}
struct Group {
    path: PathBuf,
    fd: File,
}
impl Group {
    fn new(name: &str) -> Self {
        let path = Path::new("/sys/fs/cgroup/devices").join(name);
        std::fs::create_dir(&path).unwrap();
        let fd = File::open(&path).unwrap();
        Self { path, fd }
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        std::fs::remove_dir(&self.path).unwrap();
    }
}
enum Operation {
    Open(&'static str, i32),
    Make,
    Existing(File),
}
fn in_group(group: &Group, op: Operation, expected_errno: i32) {
    let enrollment = OpenOptions::new()
        .write(true)
        .open(group.path.join("cgroup.procs"))
        .unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        if unsafe { libc::write(enrollment.as_raw_fd(), b"0".as_ptr().cast(), 1) } != 1 {
            unsafe { libc::_exit(120) };
        }
        let result = match op {
            Operation::Open(path, flags) => {
                let path = CString::new(path).unwrap();
                let fd = unsafe {
                    libc::open(path.as_ptr(), flags | libc::O_CLOEXEC | libc::O_NONBLOCK)
                };
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                }
                fd as libc::c_long
            }
            Operation::Make => unsafe {
                libc::mknod(
                    c"/dev/wros-created".as_ptr(),
                    libc::S_IFCHR | 0o600,
                    libc::makedev(1, 3),
                ) as libc::c_long
            },
            Operation::Existing(file) => unsafe {
                libc::write(file.as_raw_fd(), b"x".as_ptr().cast(), 1) as libc::c_long
            },
        };
        let errno = if result < 0 {
            std::io::Error::last_os_error().raw_os_error().unwrap()
        } else {
            0
        };
        unsafe { libc::_exit(if errno == expected_errno { 0 } else { 121 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(
        status, 0,
        "child permission outcome differed for {:?}, expected errno {expected_errno}",
        group.path
    );
}
fn rule(access: Access) -> Rule {
    Rule {
        key: Key {
            kind: Kind::Character,
            major: 1,
            minor: 3,
        },
        access,
    }
}
fn node(path: &str, minor: u32) {
    let path = CString::new(path).unwrap();
    assert_eq!(
        unsafe {
            libc::mknod(
                path.as_ptr(),
                libc::S_IFCHR | 0o600,
                libc::makedev(1, minor),
            )
        },
        0
    );
}
fn main() {
    assert_eq!(
        std::env::var("WROS_DISPOSABLE_DEVICE_GUEST").unwrap(),
        "yes"
    );
    assert_eq!(
        std::fs::read_to_string("/run/device-fixture-marker").unwrap(),
        "offline-qemu-no-hardware\n"
    );
    assert_eq!(unsafe { libc::geteuid() }, 0);
    std::fs::create_dir("/sys/fs/cgroup/devices").unwrap();
    let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    {
        let deny = Group::new("deny");
        let held = Policy::new(&[]).unwrap().attach_empty(&deny.fd).unwrap();
        for path in ["/dev/null", "/dev/zero", "/dev/full"] {
            in_group(&deny, Operation::Open(path, libc::O_RDONLY), libc::EPERM);
        }
        passed("empty-policy-denies-device-opens");
        assert!(Policy::vm().attach_empty(&deny.fd).is_err());
        in_group(
            &deny,
            Operation::Open("/dev/null", libc::O_RDWR),
            libc::EPERM,
        );
        passed("existing-policy-cannot-be-replaced");
        drop(held);
        in_group(
            &deny,
            Operation::Open("/dev/null", libc::O_RDONLY),
            libc::EPERM,
        );
        passed("closed-policy-fd-does-not-remove-enforcement");
        let child = Group::new("deny/nested");
        assert!(Policy::vm().attach_empty(&child.fd).is_err());
        in_group(
            &child,
            Operation::Open("/dev/null", libc::O_RDONLY),
            libc::EPERM,
        );
        passed("descendant-cannot-widen-ancestor-device-policy");
        let existing = OpenOptions::new().write(true).open("/dev/full").unwrap();
        in_group(&deny, Operation::Existing(existing), libc::ENOSPC);
        passed("existing-fd-boundary-is-explicit-not-revocation");
    }
    for (name, access, allowed) in [
        ("read", Access::Read, [true, false, false]),
        ("write", Access::Write, [false, true, false]),
        ("readwrite", Access::ReadWrite, [true, true, true]),
    ] {
        let g = Group::new(name);
        let _filter = Policy::new(&[rule(access)])
            .unwrap()
            .attach_empty(&g.fd)
            .unwrap();
        for (index, flags) in [libc::O_RDONLY, libc::O_WRONLY, libc::O_RDWR]
            .iter()
            .enumerate()
        {
            in_group(
                &g,
                Operation::Open("/dev/null", *flags),
                if allowed[index] { 0 } else { libc::EPERM },
            );
        }
        in_group(
            &g,
            Operation::Open("/dev/zero", libc::O_RDONLY),
            libc::EPERM,
        );
        in_group(&g, Operation::Make, libc::EPERM);
        passed(&format!("exact-{name}-without-mknod-or-wildcards"));
    }
    {
        let g = Group::new("vm");
        let _filter = Policy::vm().attach_empty(&g.fd).unwrap();
        in_group(&g, Operation::Open("/dev/null", libc::O_RDWR), 0);
        for path in ["/dev/zero", "/dev/random", "/dev/urandom"] {
            in_group(&g, Operation::Open(path, libc::O_RDONLY), 0);
            in_group(&g, Operation::Open(path, libc::O_WRONLY), libc::EPERM);
        }
        in_group(
            &g,
            Operation::Open("/dev/full", libc::O_WRONLY),
            libc::EPERM,
        );
        in_group(&g, Operation::Make, libc::EPERM);
        passed("vm-baseline-is-not-a-physical-device-grant");
        let sibling = Group::new("sibling");
        let _denied = Policy::new(&[]).unwrap().attach_empty(&sibling.fd).unwrap();
        in_group(
            &sibling,
            Operation::Open("/dev/null", libc::O_RDONLY),
            libc::EPERM,
        );
        in_group(&g, Operation::Open("/dev/null", libc::O_RDONLY), 0);
        passed("sibling-device-permissions-are-independent");
    }
    {
        let g = Group::new("populated");
        let enrollment = OpenOptions::new()
            .write(true)
            .open(g.path.join("cgroup.procs"))
            .unwrap();
        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let read = unsafe { File::from_raw_fd(pipe[0]) };
        let write = unsafe { File::from_raw_fd(pipe[1]) };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            assert_eq!(
                unsafe { libc::write(enrollment.as_raw_fd(), b"0".as_ptr().cast(), 1) },
                1
            );
            unsafe {
                libc::write(write.as_raw_fd(), b"x".as_ptr().cast(), 1);
                libc::pause();
                libc::_exit(0);
            }
        }
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::read(read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            1
        );
        assert!(Policy::vm().attach_empty(&g.fd).is_err());
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        passed("populated-cgroup-refuses-policy-installation");
    }
    assert!(Policy::vm()
        .attach_empty(&File::open("/tmp").unwrap())
        .is_err());
    passed("non-cgroup-target-rejected");
    {
        let g = Group::new("max-rules");
        let mut rules: Vec<_> = (0..127)
            .map(|minor| Rule {
                key: Key {
                    kind: Kind::Character,
                    major: 511,
                    minor,
                },
                access: Access::Read,
            })
            .collect();
        rules.push(rule(Access::Read));
        let _filter = Policy::new(&rules).unwrap().attach_empty(&g.fd).unwrap();
        in_group(&g, Operation::Open("/dev/null", libc::O_RDONLY), 0);
        in_group(
            &g,
            Operation::Open("/dev/null", libc::O_WRONLY),
            libc::EPERM,
        );
        passed("maximum-rule-budget-verified-by-real-kernel");
    }
    node("/dev/wros-alias", 3);
    let canonical = Device::inspect(Path::new("/dev/null")).unwrap();
    let alias = Device::inspect(Path::new("/dev/wros-alias")).unwrap();
    assert_eq!(canonical.key(), alias.key());
    let parent = Group::new("owner-a");
    let other = Group::new("owner-b");
    let held = ownership::claim_with_devices(&parent.path, "first", &[], &[&canonical]).unwrap();
    held.check_devices(&parent.path, "first", &[&alias])
        .unwrap();
    assert!(ownership::claim_with_devices(&other.path, "second", &[], &[&alias]).is_err());
    assert!(held.check_devices(&other.path, "first", &[&alias]).is_err());
    passed("device-node-alias-cannot-bypass-original-owner");
    drop(held);
    assert!(ownership::claim_with_devices(&other.path, "second", &[], &[&alias]).is_err());
    let held = ownership::claim_with_devices(&parent.path, "first", &[], &[&canonical]).unwrap();
    assert!(ownership::claim_with_devices(&parent.path, "first", &[], &[&alias]).is_err());
    passed("unlock-does-not-authorize-transfer-or-two-managers");
    drop(held);
    assert!(
        ownership::claim_with_devices(&parent.path, "first", &[], &[&canonical, &alias]).is_err()
    );
    passed("duplicate-device-aliases-rejected-in-one-admission");
    node("/dev/wros-changing", 5);
    let changing = Device::inspect(Path::new("/dev/wros-changing")).unwrap();
    std::fs::remove_file("/dev/wros-changing").unwrap();
    node("/dev/wros-changing", 5);
    assert!(changing.revalidate().is_err());
    assert!(ownership::claim_with_devices(&parent.path, "first", &[], &[&changing]).is_err());
    passed("same-number-replaced-inode-requires-new-review");
    std::os::unix::fs::symlink("/dev/null", "/dev/wros-link").unwrap();
    assert!(Device::inspect(Path::new("/dev/wros-link")).is_err());
    std::fs::create_dir("/dev/wros-writable").unwrap();
    node("/dev/wros-writable/node", 3);
    std::fs::set_permissions("/dev/wros-writable", std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Device::inspect(Path::new("/dev/wros-writable/node")).is_err());
    passed("device-symlinks-and-writable-ancestors-rejected");
    let zero = Device::inspect(Path::new("/dev/zero")).unwrap();
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let _owned = ownership::claim_with_devices(&parent.path, "first", &[], &[&zero]).unwrap();
        unsafe { libc::_exit(0) }; // no destructors: model abrupt manager exit
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert_eq!(status, 0);
    assert!(ownership::claim_with_devices(&other.path, "second", &[], &[&zero]).is_err());
    assert!(ownership::claim_with_devices(&parent.path, "first", &[], &[&zero]).is_ok());
    passed("manager-crash-preserves-device-owner");
    // Corrupting the root-owned registry is only a negative guest fixture.
    std::fs::write("/run/wros-ownership/device-2-1-5", b"corrupt").unwrap();
    assert!(ownership::claim_with_devices(&parent.path, "first", &[], &[&zero]).is_err());
    passed("corrupt-device-claim-fails-closed");
    drop(zero);
    drop(changing);
    drop(parent);
    drop(other);
    drop(alias);
    drop(canonical);
    assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
    passed("all-policy-and-reservation-handles-closed");
    println!("DEVICE_KERNEL_PASS");
}
