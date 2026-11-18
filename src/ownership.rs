//! Host-wide reservations for identities used by deployment-owned processes.
//!
//! Every manager uses the same administrator-owned /run/wros-ownership directory.
//! A nonblocking per-identity lock excludes concurrent managers, including two
//! invocations of the same deployment. A checksummed owner record survives a
//! manager crash: releasing a lock never authorizes another deployment to adopt
//! that identity while old children might still exist. Only the original cgroup
//! parent and deployment name may reacquire it. Records persist in /run;
//! they are not credentials, recovery approval or device-access enforcement.
use crate::manifest::{Process, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const DIRECTORY: &str = "/run/wros-ownership";
const MAGIC: &[u8] = b"WROS-host-identity\0";
const MAX_IDENTITIES: usize = 256;

/// Keep these descriptors in the manager through the complete shutdown path.
/// CLOEXEC prevents their inheritance into VM or native-provider executables.
pub struct Reservations {
    _locks: Vec<File>,
    owner: [u8; 32],
    identities: BTreeSet<String>,
    process: libc::pid_t,
}
impl Reservations {
    /// A held reservation can cover the subset selected for an approved cold
    /// start, but never another owner, process incarnation or extra identity.
    pub(crate) fn check(
        &self,
        parent: &Path,
        deployment: &str,
        processes: &[&Process],
    ) -> Result<()> {
        if self.process != unsafe { libc::getpid() }
            || self.owner != owner(parent, deployment)?
            || processes.iter().any(|p| {
                p.identity.is_none_or(|(uid, gid)| {
                    !self.identities.contains(&format!("uid-{uid}"))
                        || !self.identities.contains(&format!("gid-{gid}"))
                })
            })
        {
            return Err("held identity reservations do not cover this deployment".into());
        }
        Ok(())
    }
}

fn private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err("identity registry requires private owner-only files and directory".into());
    }
    Ok(())
}
fn open_at(directory: &File, name: &str, flags: i32) -> std::io::Result<File> {
    let name = CString::new(name).map_err(std::io::Error::other)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn lock(file: &File) -> Result<()> {
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(
            "host identity is busy; connect through its original deployment manager".into(),
        );
    }
    Ok(())
}
fn owner(parent: &Path, deployment: &str) -> Result<[u8; 32]> {
    if deployment.is_empty()
        || deployment.len() > 128
        || !deployment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || !parent.is_absolute()
        || parent.canonicalize().map_err(|e| e.to_string())? != parent
    {
        return Err("identity owner requires an exact cgroup parent and deployment name".into());
    }
    let mut h = Sha256::new();
    for value in [
        b"WROS identity owner".as_slice(),
        parent.as_os_str().as_encoded_bytes(),
        deployment.as_bytes(),
    ] {
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    }
    Ok(h.finalize().into())
}
fn record(owner: &[u8; 32], name: &str) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(owner);
    bytes.extend(name.as_bytes());
    bytes.extend(Sha256::digest(&bytes));
    bytes
}

/// Validate the entire request and every existing owner before publishing any
/// new claim. I/O failure may leave conservative partial reservations or a
/// malformed file; neither permits execution or takeover. Never delete claims
/// on failure, on ordinary shutdown, or merely because their lock is available.
fn reserve(directory: File, owner: [u8; 32], identities: &[String]) -> Result<Reservations> {
    private(&directory, true)?;
    if identities.is_empty() || identities.len() > MAX_IDENTITIES {
        return Err("invalid identity reservation count".into());
    }
    let mut ordered = BTreeSet::new();
    for name in identities {
        let (kind, number) = name.split_once('-').ok_or("invalid host identity")?;
        let n = number.parse::<u32>().map_err(|_| "invalid host identity")?;
        if !matches!(kind, "uid" | "gid")
            || n == 0
            || n == u32::MAX
            || n.to_string() != number
            || !ordered.insert(name)
        {
            return Err("invalid or duplicate host identity".into());
        }
    }
    let admission =
        open_at(&directory, "lock", libc::O_RDWR | libc::O_CREAT).map_err(|e| e.to_string())?;
    private(&admission, false)?;
    lock(&admission)?;
    // The same cgroup owner cannot run two managers even if a stale approved
    // configuration uses a different set of UIDs. Otherwise its reclaim step
    // could kill the current deployment without hitting an identity conflict.
    let name = format!(
        "deployment-{}",
        owner.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let deployment =
        open_at(&directory, &name, libc::O_RDWR | libc::O_CREAT).map_err(|e| e.to_string())?;
    private(&deployment, false)?;
    lock(&deployment)?;
    let mut locks = vec![deployment];
    let mut missing = Vec::new();
    for name in ordered {
        match open_at(&directory, name, libc::O_RDWR) {
            Ok(mut file) => {
                private(&file, false)?;
                lock(&file)?;
                let expected = record(&owner, name);
                let mut bytes = Vec::new();
                (&mut file)
                    .take((expected.len() + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                if bytes != expected {
                    return Err(format!("host identity {name} belongs to another deployment or has an invalid record; use the original deployment manager"));
                }
                locks.push(file);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing.push(name),
            Err(e) => return Err(e.to_string()),
        }
    }
    for name in missing {
        let mut file = open_at(
            &directory,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|e| e.to_string())?;
        private(&file, false)?;
        lock(&file)?;
        file.write_all(&record(&owner, name))
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        locks.push(file);
    }
    directory.sync_all().map_err(|e| e.to_string())?;
    Ok(Reservations {
        _locks: locks,
        owner,
        identities: identities.iter().cloned().collect(),
        process: unsafe { libc::getpid() },
    })
}

/// Claim all final UID/GID values before creating any workload. The platform
/// must share this registry across managers and reserve these OS identities for
/// WROS. Private /run mounts or an unmanaged process using the same UID are not
/// made safe by advisory locks. Root remains the trusted provisioning authority.
pub fn claim(parent: &Path, deployment: &str, processes: &[&Process]) -> Result<Reservations> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("identity reservation requires the privileged deployment supervisor".into());
    }
    crate::cgroup::directory(parent)?;
    let owner = owner(parent, deployment)?;
    // /run is an administrator-owned, non-aliased directory. Open its child
    // relative to the pinned descriptor; never follow a registry symlink.
    if Path::new("/run")
        .canonicalize()
        .map_err(|e| e.to_string())?
        != Path::new("/run")
    {
        return Err("host identity registry requires a non-aliased /run".into());
    }
    let run = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/run")
        .map_err(|e| e.to_string())?;
    let info = run.metadata().map_err(|e| e.to_string())?;
    if info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err("/run must be root-owned and not writable by guests".into());
    }
    if unsafe { libc::mkdirat(run.as_raw_fd(), c"wros-ownership".as_ptr(), 0o700) } != 0
        && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let directory = open_at(&run, "wros-ownership", libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|e| e.to_string())?;
    let identities = processes
        .iter()
        .map(|p| p.identity.ok_or("missing guest identity"))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flat_map(|(uid, gid)| [format!("uid-{uid}"), format!("gid-{gid}")])
        .collect::<Vec<_>>();
    reserve(directory, owner, &identities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let mut random = [0u8; 16];
            File::open("/dev/urandom")
                .unwrap()
                .read_exact(&mut random)
                .unwrap();
            let base = std::env::var_os("WROS_TEST_DIRECTORY")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let p = base.join(format!("ownership-{:032x}", u128::from_le_bytes(random)));
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn open(&self) -> File {
            File::open(&self.0).unwrap()
        }
        fn claim(&self, who: u8, names: &[&str]) -> Result<Reservations> {
            reserve(
                self.open(),
                [who; 32],
                &names.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn live_owner_and_old_owner_both_prevent_takeover() {
        let f = Fixture::new();
        let hold = f.claim(1, &["uid-10001", "gid-10001"]).unwrap();
        assert!(f.claim(1, &["uid-10001"]).is_err());
        assert!(f.claim(1, &["uid-11001", "gid-11001"]).is_err());
        assert!(f.claim(2, &["gid-10001"]).is_err());
        drop(hold);
        assert!(f.claim(2, &["uid-10001"]).is_err());
        assert!(f.claim(1, &["uid-10001", "gid-10001"]).is_ok());
    }
    #[test]
    fn failed_batch_does_not_publish_free_identities() {
        let f = Fixture::new();
        drop(f.claim(1, &["uid-10002"]).unwrap());
        assert!(f.claim(2, &["gid-10003", "uid-10002"]).is_err());
        assert!(!f.0.join("gid-10003").exists());
        assert!(f.claim(2, &["gid-10004"]).is_ok());
    }
    #[test]
    fn manager_death_releases_lock_but_preserves_original_owner() {
        let f = Fixture::new();
        let hold = f.claim(1, &["uid-10001"]).unwrap();
        let mut pipe = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe {
                libc::close(pipe[1]);
                let mut byte = 0u8;
                libc::read(pipe[0], (&mut byte as *mut u8).cast(), 1);
                libc::_exit(0);
            }
        }
        unsafe {
            libc::close(pipe[0]);
        }
        drop(hold);
        assert!(f.claim(1, &["uid-10001"]).is_err());
        let mut status = 0;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        unsafe {
            libc::close(pipe[1]);
        }
        assert!(f.claim(2, &["uid-10001"]).is_err());
        assert!(f.claim(1, &["uid-10001"]).is_ok());
    }
    #[test]
    fn malformed_private_records_and_links_fail_closed() {
        let f = Fixture::new();
        drop(f.claim(1, &["uid-10001"]).unwrap());
        let p = f.0.join("uid-10001");
        std::fs::write(&p, b"truncated").unwrap();
        assert!(f.claim(1, &["uid-10001"]).is_err());
        std::fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink("missing", &p).unwrap();
        assert!(f.claim(1, &["uid-10001"]).is_err());
        std::fs::remove_file(&p).unwrap();
        drop(f.claim(1, &["uid-10001"]).unwrap());
        std::fs::hard_link(&p, f.0.join("alias")).unwrap();
        assert!(f.claim(1, &["uid-10001"]).is_err());
        std::fs::remove_file(f.0.join("alias")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.claim(1, &["uid-10001"]).is_err());
    }
    #[test]
    fn canonical_bounded_identities_and_owner() {
        let f = Fixture::new();
        for names in [
            &[][..],
            &["uid-0"],
            &["gid-4294967295"],
            &["uid-01"],
            &["uid-1", "uid-1"],
            &["../uid-1"],
            &["device-1"],
        ] {
            assert!(f.claim(1, names).is_err());
        }
        assert_ne!(owner(&f.0, "one").unwrap(), owner(&f.0, "two").unwrap());
        assert!(owner(&f.0, "../one").is_err());
        assert!(owner(Path::new("."), "one").is_err());
        let held = f.claim(1, &["uid-10001"]).unwrap();
        for fd in &held._locks {
            assert_ne!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
    }
    #[test]
    fn held_reservations_cannot_authorize_another_scope_or_identity() {
        let f = Fixture::new();
        let xml = format!(
            r#"<deployment id="one"><vm id="vm" module="body.wasm" sha256="{}" policy="body.policy" memory-bytes="1024" pids="1" uid="10001" gid="10001"/></deployment>"#,
            "a".repeat(64)
        );
        let mut plan = crate::manifest::deployment(&xml).unwrap();
        let held = reserve(
            f.open(),
            owner(&f.0, "one").unwrap(),
            &["uid-10001".into(), "gid-10001".into()],
        )
        .unwrap();
        assert!(held.check(&f.0, "one", &[&plan.processes[0]]).is_ok());
        assert!(held.check(&f.0, "one", &[]).is_ok());
        assert!(held.check(&f.0, "other", &[&plan.processes[0]]).is_err());
        plan.processes[0].identity = Some((10002, 10001));
        assert!(held.check(&f.0, "one", &[&plan.processes[0]]).is_err());
    }
}
