//! Provision immutable, mutually authenticated local driver attachments.
//!
//! This module owns no process lifecycle and grants no device or motion rights.
//! The privileged supervisor must first isolate both children, pin their time
//! namespaces, and admit their identities/resources. Only that supervisor may
//! pass these descriptors. Guest-facing traffic uses the VM's pinned TLS 1.3
//! Ed25519 RPK / X25519 / AES-128-GCM profile; no plaintext fallback exists.
//! Keys are freshly generated for each endpoint, never serialized to XML,
//! arguments, environment or a persistent file. Sealed memfds remain readable
//! by their intended holder until closed; sealing is not secret erasure.
use crate::manifest::Result;
use ed25519_dalek::SigningKey;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const BOOTSTRAP_BYTES: usize = 256;
pub const MAGIC: u64 = u64::from_le_bytes(*b"WROSDRV\0");
pub const TLS_ED25519_X25519_AES128GCM: u64 = 1;
pub const SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
pub const READY: &[u8; 10] = b"WROS-READY";
pub const DELIVERY: &[u8; 8] = b"WROS-FDS";
type Id = [u8; 16];

fn os_error() -> String {
    std::io::Error::last_os_error().to_string()
}
fn owned(fd: i32) -> Result<File> {
    if fd < 0 {
        return Err(os_error());
    }
    // Never let stdio redirection replace a retained provisioning object.
    let file = unsafe { File::from_raw_fd(fd) };
    crate::supervisor::retained(file)
}
fn entropy(bytes: &mut [u8]) -> Result<()> {
    let mut at = 0;
    for _ in 0..32 {
        if at == bytes.len() {
            return Ok(());
        }
        let n = unsafe {
            libc::getrandom(
                bytes[at..].as_mut_ptr().cast(),
                bytes.len() - at,
                libc::GRND_NONBLOCK,
            )
        };
        if n > 0 {
            at += n as usize;
        } else if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return Err("kernel entropy unavailable; refusing attachment creation".into());
        }
    }
    Err("kernel entropy retry budget exhausted".into())
}
/// A fresh nonzero opaque identifier. Never substitute a clock or PID for entropy.
pub fn identifier() -> Result<Id> {
    let mut id = [0; 16];
    entropy(&mut id)?;
    if id == [0; 16] {
        return Err("invalid random identifier".into());
    }
    Ok(id)
}
fn seal(name: &'static std::ffi::CStr, bytes: &[u8]) -> Result<File> {
    let mut file = owned(unsafe {
        libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    })?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o400) } != 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, SEALS) } != 0
    {
        return Err(os_error());
    }
    Ok(file)
}
/// A dedicated local carrier, already nonblocking, CLOEXEC and credential-tagged.
/// No pathname, listener or network address can be selected by a guest.
pub fn carrier() -> Result<[File; 2]> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(os_error());
    }
    // Adopt both raw descriptors before any fallible operation.
    let raw = fds.map(|fd| unsafe { File::from_raw_fd(fd) });
    let [a, b] = raw;
    let pair = [
        crate::supervisor::retained(a)?,
        crate::supervisor::retained(b)?,
    ];
    for file in &pair {
        let yes: i32 = 1;
        if unsafe {
            libc::setsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&yes as *const i32).cast(),
                4,
            )
        } != 0
        {
            return Err(os_error());
        }
    }
    Ok(pair)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub deployment: Id,
    pub vm: Id,
    pub scope: Id,
    pub provider: Id,
    pub session: Id,
    pub contract: [u8; 32],
}
impl Binding {
    pub fn fresh(
        deployment: Id,
        vm: Id,
        scope: Id,
        provider: Id,
        contract: [u8; 32],
    ) -> Result<Self> {
        let value = Self {
            deployment,
            vm,
            scope,
            provider,
            session: identifier()?,
            contract,
        };
        value.check()?;
        Ok(value)
    }
    fn check(&self) -> Result<()> {
        if [
            self.deployment,
            self.vm,
            self.scope,
            self.provider,
            self.session,
        ]
        .contains(&[0; 16])
            || self.contract == [0; 32]
        {
            return Err("attachment requires every identity and a contract digest".into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_ns: u64,
    pub session_until_ns: u64,
}
impl Limits {
    fn check(&self) -> Result<()> {
        if self.request_bytes == 0
            || self.request_bytes > 65536
            || self.response_bytes == 0
            || self.response_bytes > 65536
            || self.request_ns == 0
            || self.request_ns > i64::MAX as u64
            || self.session_until_ns <= monotonic_ns()?
            || self.session_until_ns > i64::MAX as u64
        {
            return Err("invalid or expired attachment budget".into());
        }
        Ok(())
    }
}
pub fn monotonic_ns() -> Result<u64> {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0
        || now.tv_sec < 0
        || !(0..1_000_000_000).contains(&now.tv_nsec)
    {
        return Err("monotonic clock unavailable".into());
    }
    (now.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|x| x.checked_add(now.tv_nsec as u64))
        .ok_or("monotonic clock overflow".into())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Credentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}
impl Credentials {
    fn check(&self) -> Result<()> {
        if self.pid == 0
            || self.pid > i32::MAX as u32
            || self.uid == u32::MAX
            || self.gid == u32::MAX
        {
            return Err("invalid attachment credentials".into());
        }
        Ok(())
    }
}
/// Keep the exact process incarnation alive as evidence while inspecting procfs.
/// The caller must have installed the namespace-pinning filter before pinning.
/// Checking a namespace FD alone cannot prove which filter a process installed.
pub struct Peer {
    credentials: Credentials,
    lifetime: File,
    clock: File,
}
impl Peer {
    pub fn pin(credentials: Credentials) -> Result<Self> {
        credentials.check()?;
        let lifetime =
            owned(unsafe { libc::syscall(libc::SYS_pidfd_open, credentials.pid, 0) } as i32)?;
        let live = || {
            let mut p = libc::pollfd {
                fd: lifetime.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut p, 1, 0) == 0 }
        };
        if !live() {
            return Err("attachment peer has exited".into());
        }
        let mut text = String::new();
        File::open(format!("/proc/{}/status", credentials.pid))
            .map_err(|e| e.to_string())?
            .take(65537)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        if text.len() > 65536 {
            return Err("peer status exceeds limit".into());
        }
        for (name, expected) in [("Uid:", credentials.uid), ("Gid:", credentials.gid)] {
            let fields: Vec<_> = text.lines().filter_map(|x| x.strip_prefix(name)).collect();
            if fields.len() != 1
                || fields[0].split_whitespace().collect::<Vec<_>>() != vec![expected.to_string(); 4]
            {
                return Err("peer credentials differ from the approved identity".into());
            }
        }
        let clock = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/proc/{}/ns/time", credentials.pid))
            .map_err(|e| e.to_string())?;
        let clock = crate::supervisor::retained(clock)?;
        let local = File::open("/proc/self/ns/time")
            .map_err(|e| e.to_string())?
            .metadata()
            .map_err(|e| e.to_string())?;
        let remote = clock.metadata().map_err(|e| e.to_string())?;
        // NS_GET_NSTYPE is _IO(0xb7, 3), architecture-independent on these Linux ABIs.
        if unsafe { libc::ioctl(clock.as_raw_fd(), 0xb703) } != libc::CLONE_NEWTIME
            || (local.dev(), local.ino()) != (remote.dev(), remote.ino())
            || !live()
        {
            return Err("peer clock namespace does not match the provisioner".into());
        }
        Ok(Self {
            credentials,
            lifetime,
            clock,
        })
    }
    pub fn credentials(&self) -> Credentials {
        self.credentials
    }
    pub fn clock(&self) -> &File {
        &self.clock
    }
    pub fn live(&self) -> bool {
        let mut p = libc::pollfd {
            fd: self.lifetime.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut p, 1, 0) == 0 }
    }
}

/// Ownership is exclusive. Dropping an endpoint closes only local descriptors;
/// it never shuts down the other holder's socket or signals either child.
pub struct Endpoint {
    channel: File,
    identity: File,
}
impl Endpoint {
    pub fn channel(&self) -> &File {
        &self.channel
    }
    pub fn identity(&self) -> &File {
        &self.identity
    }
    /// Freeze one external provider's bootstrap after both final PIDs are known.
    /// All numeric fields are LE u64; the five identifiers/digest retain byte order.
    pub fn bootstrap(
        &self,
        binding: Binding,
        limits: Limits,
        local: &Peer,
        remote: &Peer,
    ) -> Result<File> {
        binding.check()?;
        limits.check()?;
        if local.credentials.pid == remote.credentials.pid || !local.live() || !remote.live() {
            return Err("attachment requires two live, distinct process incarnations".into());
        }
        let socket = self.channel.metadata().map_err(|e| e.to_string())?;
        let clock = remote.clock.metadata().map_err(|e| e.to_string())?;
        let mut record = [0u8; BOOTSTRAP_BYTES];
        let mut at = 0;
        for word in [
            MAGIC,
            BOOTSTRAP_BYTES as u64,
            1,
            TLS_ED25519_X25519_AES128GCM,
            local.credentials.pid as u64,
            local.credentials.uid as u64,
            local.credentials.gid as u64,
            remote.credentials.pid as u64,
            remote.credentials.uid as u64,
            remote.credentials.gid as u64,
        ] {
            record[at..at + 8].copy_from_slice(&word.to_le_bytes());
            at += 8;
        }
        for id in [
            binding.deployment,
            binding.vm,
            binding.scope,
            binding.provider,
            binding.session,
        ] {
            record[at..at + 16].copy_from_slice(&id);
            at += 16;
        }
        record[at..at + 32].copy_from_slice(&binding.contract);
        at += 32;
        for word in [
            limits.request_bytes,
            limits.response_bytes,
            limits.request_ns,
            limits.session_until_ns,
            socket.dev(),
            socket.ino(),
            clock.dev(),
            clock.ino(),
        ] {
            record[at..at + 8].copy_from_slice(&word.to_le_bytes());
            at += 8;
        }
        seal(c"wros-driver-bootstrap", &record)
    }
}
/// Two fresh Ed25519 seeds and exact reciprocal public-key pins. This is key
/// provisioning, not a replacement for TLS or for independent receiver policy.
pub fn endpoints() -> Result<[Endpoint; 2]> {
    let mut seeds = Zeroizing::new([[0u8; 32]; 2]);
    for seed in seeds.iter_mut() {
        entropy(seed)?;
    }
    let left = SigningKey::from_bytes(&seeds[0]);
    let right = SigningKey::from_bytes(&seeds[1]);
    if left.verifying_key() == right.verifying_key() {
        return Err("duplicate random attachment keys".into());
    }
    let mut records = Zeroizing::new([[0u8; 64]; 2]);
    records[0][..32].copy_from_slice(left.as_bytes());
    records[0][32..].copy_from_slice(right.verifying_key().as_bytes());
    records[1][..32].copy_from_slice(right.as_bytes());
    records[1][32..].copy_from_slice(left.verifying_key().as_bytes());
    let a = seal(c"wros-attachment-identity", &records[0])?;
    let b = seal(c"wros-attachment-identity", &records[1])?;
    let [channel_a, channel_b] = carrier()?;
    Ok([
        Endpoint {
            channel: channel_a,
            identity: a,
        },
        Endpoint {
            channel: channel_b,
            identity: b,
        },
    ])
}

/// Transfer exactly four provisioner-owned descriptors once, after a READY
/// packet with the child's kernel credentials. This private inherited bootstrap
/// socket is not a guest service. No key bytes appear in its messages. The
/// receiver must verify the provisioner's credentials, exact descriptor count,
/// record seals/binding and endpoint identities before beginning mutual TLS.
/// No received descriptors are accepted here, including on malformed input.
pub fn deliver(
    courier: &File,
    endpoint: Endpoint,
    record: File,
    local: &Peer,
    remote: &Peer,
    timeout: Duration,
) -> Result<()> {
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err("invalid bootstrap deadline".into());
    }
    let until = Instant::now() + timeout;
    let mut ready = false;
    while Instant::now() < until {
        if !local.live() || !remote.live() {
            return Err("bootstrap peer exited".into());
        }
        if !ready {
            let mut bytes = [0u8; 16];
            // Admit the complete Linux SCM_MAX_FD set into bounded temporary
            // storage, then close and reject it. This avoids depending on an
            // emulator to close descriptors omitted by ancillary translation.
            // The protocol never accepts even one descriptor in READY.
            let mut control = [0usize; 1152 / std::mem::size_of::<usize>()];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = std::mem::size_of_val(&control);
            let n = unsafe {
                libc::recvmsg(
                    courier.as_raw_fd(),
                    &mut msg,
                    libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
                )
            };
            if n < 0 {
                if !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR)
                ) {
                    return Err(os_error());
                }
            } else {
                let mut found = 0;
                let mut bad = msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
                unsafe {
                    let mut c = libc::CMSG_FIRSTHDR(&msg);
                    while !c.is_null() {
                        if (*c).cmsg_len < libc::CMSG_LEN(0) as usize {
                            bad = true;
                            break;
                        }
                        if (*c).cmsg_level == libc::SOL_SOCKET && (*c).cmsg_type == libc::SCM_RIGHTS
                        {
                            let count = ((*c).cmsg_len - libc::CMSG_LEN(0) as usize)
                                / std::mem::size_of::<i32>();
                            for i in 0..count {
                                libc::close(std::ptr::read_unaligned(
                                    libc::CMSG_DATA(c).cast::<i32>().add(i),
                                ));
                            }
                            bad = true;
                        } else if (*c).cmsg_level == libc::SOL_SOCKET
                            && (*c).cmsg_type == libc::SCM_CREDENTIALS
                            && (*c).cmsg_len
                                == libc::CMSG_LEN(std::mem::size_of::<libc::ucred>() as u32)
                                    as usize
                        {
                            let cred =
                                std::ptr::read_unaligned(libc::CMSG_DATA(c).cast::<libc::ucred>());
                            found += 1;
                            bad |= Credentials {
                                pid: cred.pid as u32,
                                uid: cred.uid,
                                gid: cred.gid,
                            } != local.credentials;
                        } else {
                            bad = true;
                        }
                        c = libc::CMSG_NXTHDR(&msg, c);
                    }
                }
                if bad || found != 1 || n != READY.len() as isize || &bytes[..READY.len()] != READY
                {
                    return Err("invalid bootstrap readiness or credentials".into());
                }
                ready = true;
            }
        }
        if ready {
            let fds = [
                endpoint.channel.as_raw_fd(),
                endpoint.identity.as_raw_fd(),
                remote.clock.as_raw_fd(),
                record.as_raw_fd(),
            ];
            let mut control = [0usize; 8];
            let mut iov = libc::iovec {
                iov_base: DELIVERY.as_ptr().cast_mut().cast(),
                iov_len: DELIVERY.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen =
                unsafe { libc::CMSG_SPACE(std::mem::size_of_val(&fds) as u32) } as usize;
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&fds) as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    fds.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(c),
                    std::mem::size_of_val(&fds),
                );
            }
            let n = unsafe {
                libc::sendmsg(
                    courier.as_raw_fd(),
                    &msg,
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                )
            };
            if n == DELIVERY.len() as isize {
                return Ok(());
            }
            if n >= 0
                || !matches!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EAGAIN | libc::EINTR)
                )
            {
                return Err("bootstrap descriptor delivery failed".into());
            }
        }
        let mut p = libc::pollfd {
            fd: courier.as_raw_fd(),
            events: if ready { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        unsafe {
            libc::poll(&mut p, 1, 1);
        }
    }
    Err("bootstrap deadline expired".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    #[test]
    fn maximum_descriptor_injection_is_closed_and_denied() {
        let [sender, receiver] = carrier().unwrap();
        let [wake, wait] = carrier().unwrap();
        let [endpoint, _other] = endpoints().unwrap();
        // Track the kernel objects owned by this test. Other libtest threads may
        // open or close unrelated descriptors while the delivery is in progress.
        let identity = |file: &File| {
            let metadata = file.metadata().unwrap();
            (metadata.dev(), metadata.ino())
        };
        let injected = identity(&receiver);
        // Prepare everything the child needs before fork; its branch only uses
        // libc syscalls and stack storage, with no Rust allocator or test output.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let mut control = [0usize; 1152 / std::mem::size_of::<usize>()];
            let files = [receiver.as_raw_fd(); 253];
            unsafe {
                libc::close(sender.as_raw_fd());
                libc::close(wake.as_raw_fd());
                let mut vector = libc::iovec {
                    iov_base: READY.as_ptr().cast_mut().cast(),
                    iov_len: READY.len(),
                };
                let mut message: libc::msghdr = std::mem::zeroed();
                message.msg_iov = &mut vector;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen =
                    libc::CMSG_SPACE(std::mem::size_of_val(&files) as u32) as usize;
                let c = libc::CMSG_FIRSTHDR(&message);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(&files) as u32) as usize;
                std::ptr::copy_nonoverlapping(
                    files.as_ptr().cast::<u8>(),
                    libc::CMSG_DATA(c),
                    std::mem::size_of_val(&files),
                );
                let n = libc::sendmsg(receiver.as_raw_fd(), &message, libc::MSG_NOSIGNAL);
                let mut event = libc::pollfd {
                    fd: wait.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                libc::poll(&mut event, 1, 5000);
                libc::_exit(if n == READY.len() as isize { 0 } else { 1 });
            }
        }
        drop(receiver);
        drop(wait);
        struct Reap(libc::pid_t);
        impl Drop for Reap {
            fn drop(&mut self) {
                if self.0 > 0 {
                    unsafe {
                        libc::kill(self.0, libc::SIGKILL);
                        libc::waitpid(self.0, std::ptr::null_mut(), 0);
                    }
                }
            }
        }
        let mut reap = Reap(child);
        let credentials = |pid| Credentials {
            pid,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };
        // Isolate delivery's ancillary-data rejection and lifetime checks. The
        // real Peer::pin namespace ioctl is exercised by the full-kernel VM
        // harness; QEMU user emulation does not implement NS_GET_NSTYPE. Do not
        // weaken that production check to make this component test pass.
        let evidence = |pid| Peer {
            credentials: credentials(pid),
            lifetime: owned(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32).unwrap(),
            clock: File::open(format!("/proc/{pid}/ns/time")).unwrap(),
        };
        let local = evidence(child as u32);
        let remote = evidence(std::process::id());
        let binding = Binding::fresh([1; 16], [2; 16], [3; 16], [4; 16], [5; 32]).unwrap();
        let limits = Limits {
            request_bytes: 32,
            response_bytes: 32,
            request_ns: 1000,
            session_until_ns: monotonic_ns().unwrap() + 1_000_000_000,
        };
        let record = endpoint
            .bootstrap(binding, limits, &local, &remote)
            .unwrap();
        let watched = [
            injected,
            identity(endpoint.channel()),
            identity(endpoint.identity()),
            identity(&record),
        ];
        let tracked_descriptors = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter_map(|path| match std::fs::metadata(path) {
                    Ok(metadata) => Some((metadata.dev(), metadata.ino())),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("could not inspect open descriptor: {error}"),
                })
                .filter(|object| watched.contains(object))
                .count()
        };
        assert_eq!(tracked_descriptors(), 3);
        assert!(deliver(
            &sender,
            endpoint,
            record,
            &local,
            &remote,
            Duration::from_secs(1)
        )
        .is_err());
        assert_eq!(tracked_descriptors(), 0);
        drop(wake);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        reap.0 = 0;
        assert_eq!(status, 0);
    }
    #[test]
    fn reciprocal_keys_are_fresh_sealed_and_close_on_exec() {
        let pairs = [endpoints().unwrap(), endpoints().unwrap()];
        let mut public = Vec::new();
        for pair in &pairs {
            let mut records = Zeroizing::new([[0u8; 64]; 2]);
            for (i, p) in pair.iter().enumerate() {
                p.identity.read_exact_at(&mut records[i], 0).unwrap();
                assert_eq!(p.identity.metadata().unwrap().len(), 64);
                assert_eq!(
                    unsafe { libc::fcntl(p.identity.as_raw_fd(), libc::F_GET_SEALS) },
                    SEALS
                );
                for f in [&p.identity, &p.channel] {
                    assert!(
                        unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC
                            != 0
                    );
                }
                assert!(p.identity.write_at(&[0], 0).is_err());
                assert!(p.identity.set_len(0).is_err());
                public.push(
                    SigningKey::from_bytes(records[i][..32].try_into().unwrap())
                        .verifying_key()
                        .to_bytes(),
                );
            }
            for i in 0..2 {
                assert_eq!(
                    &records[i][32..],
                    SigningKey::from_bytes(records[1 - i][..32].try_into().unwrap())
                        .verifying_key()
                        .as_bytes()
                );
            }
        }
        for i in 0..4 {
            for j in i + 1..4 {
                assert_ne!(public[i], public[j]);
            }
        }
    }
    #[test]
    fn rfc8032_public_key_vector() {
        let seed = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        assert_eq!(
            SigningKey::from_bytes(&seed).verifying_key().as_bytes(),
            &expected
        );
    }
    #[test]
    fn reject_missing_binding_and_expired_budget() {
        assert!(Binding::fresh([0; 16], [1; 16], [2; 16], [3; 16], [4; 32]).is_err());
        let a = Binding::fresh([1; 16], [2; 16], [3; 16], [4; 16], [5; 32]).unwrap();
        let b = Binding::fresh([1; 16], [2; 16], [3; 16], [4; 16], [5; 32]).unwrap();
        assert_ne!(a.session, b.session);
        let mut limits = Limits {
            request_bytes: 32,
            response_bytes: 32,
            request_ns: 100,
            session_until_ns: monotonic_ns().unwrap() + 1_000_000_000,
        };
        limits.check().unwrap();
        limits.request_bytes = 65537;
        assert!(limits.check().is_err());
        limits.request_bytes = 32;
        limits.session_until_ns = 0;
        assert!(limits.check().is_err());
        limits.session_until_ns = u64::MAX;
        assert!(limits.check().is_err());
    }
}
