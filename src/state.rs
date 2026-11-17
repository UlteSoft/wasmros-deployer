//! Durable approval and cold-start accounting owned by the deployment supervisor.
//!
//! The directory is an administrator-owned 0700 directory outside the bundle.
//! An exclusive lock covers admission, execution and cleanup. Each transition is
//! a bounded, checksummed record replaced with file-then-directory fsync before
//! a new generation executes. This is crash consistency, not protection against
//! an administrator rolling storage back. No guest receives a state descriptor.
use crate::manifest::{Process, Result};
use crate::verdict::Signature;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_RECORD: usize = 1024 * 1024;
const MAGIC: &[u8] = b"WROS-approved-cold-start\0";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ready,
    Running,
    Faulted,
    Ended,
    Stopped,
    Blocked,
}
#[derive(Clone, Debug)]
pub struct Entry {
    pub rights: BTreeMap<String, bool>,
    pub waiver: Option<Signature>,
    phase: Phase,
    pub generation: u64,
    pub restarts: u32,
}
impl Entry {
    pub fn reviewed(rights: BTreeMap<String, bool>, waiver: Option<Signature>) -> Self {
        Self {
            rights,
            waiver,
            phase: Phase::Ready,
            generation: 0,
            restarts: 0,
        }
    }
}
#[derive(Clone, Debug)]
struct Record {
    binding: String,
    boot: String,
    entries: BTreeMap<String, Entry>,
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn boot(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub fn boot_id() -> Result<String> {
    let mut value = String::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .and_then(|f| f.take(38).read_to_string(&mut value))
        .map_err(|e| e.to_string())?;
    let value = value.trim().to_owned();
    if !boot(&value) {
        return Err("invalid kernel boot identity".into());
    }
    Ok(value)
}
fn text(out: &mut Vec<u8>, value: &str) {
    out.extend((value.len() as u32).to_le_bytes());
    out.extend(value.as_bytes());
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let value = self.0.get(..n).ok_or("truncated approval record")?;
        self.0 = &self.0[n..];
        Ok(value)
    }
    fn number(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn string(&mut self, max: usize) -> Result<String> {
        let n = self.number()? as usize;
        if n > max {
            return Err("approval field exceeds budget".into());
        }
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "invalid approval text".into())
    }
}
impl Record {
    fn resume(&mut self, boot: String, processes: &[&Process]) -> Result<Vec<String>> {
        let new_boot = self.boot != boot;
        if self.entries.len() != processes.len()
            || processes
                .iter()
                .map(|p| &p.id)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != processes.len()
            || processes.iter().any(|p| !self.entries.contains_key(&p.id))
        {
            return Err("approved instance set changed".into());
        }
        let mut selected = Vec::new();
        for p in processes {
            let e = self.entries.get_mut(&p.id).unwrap();
            let allowed = if new_boot {
                p.boot_start
            } else {
                p.crash_restart
                    && e.restarts < p.restart_limit
                    && matches!(e.phase, Phase::Ready | Phase::Running | Phase::Faulted)
            };
            if allowed {
                e.restarts = if new_boot { 0 } else { e.restarts + 1 };
                e.phase = Phase::Ready;
                selected.push(p.id.clone());
            } else if new_boot {
                e.phase = Phase::Stopped;
                e.restarts = 0;
            } else if matches!(e.phase, Phase::Ready | Phase::Running | Phase::Faulted) {
                e.phase = Phase::Blocked;
            }
        }
        self.boot = boot;
        Ok(selected)
    }

    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = MAGIC.to_vec();
        text(&mut out, &self.binding);
        text(&mut out, &self.boot);
        out.extend((self.entries.len() as u32).to_le_bytes());
        for (name, e) in &self.entries {
            text(&mut out, name);
            out.push(match e.phase {
                Phase::Ready => 0,
                Phase::Running => 1,
                Phase::Faulted => 2,
                Phase::Ended => 3,
                Phase::Stopped => 4,
                Phase::Blocked => 5,
            });
            out.extend(e.generation.to_le_bytes());
            out.extend(e.restarts.to_le_bytes());
            out.push(match e.waiver {
                None => 0,
                Some(Signature::Unsigned) => 1,
                Some(Signature::Invalid) => 2,
                Some(Signature::Verified) => {
                    return Err("verified signatures need no waiver".into())
                }
            });
            out.extend((e.rights.len() as u32).to_le_bytes());
            for (name, allow) in &e.rights {
                text(&mut out, name);
                out.push(u8::from(*allow));
            }
        }
        let digest = Sha256::digest(&out);
        out.extend(digest);
        // The decoder validates the same closed schema for both writers and readers.
        Self::decode(&out)?;
        Ok(out)
    }
    fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_RECORD || input.len() < MAGIC.len() + 32 {
            return Err("invalid approval record size".into());
        }
        let (body, hash) = input.split_at(input.len() - 32);
        if &Sha256::digest(body)[..] != hash {
            return Err("approval record checksum mismatch".into());
        }
        let mut r = Reader(body);
        if r.take(MAGIC.len())? != MAGIC {
            return Err("unsupported approval record".into());
        }
        let binding = r.string(64)?;
        if binding.len() != 64
            || !binding
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid approval binding".into());
        }
        let boot = r.string(36)?;
        if !boot_id_valid(&boot) {
            return Err("invalid approval boot identity".into());
        }
        let n = r.number()?;
        if n == 0 || n > 128 {
            return Err("invalid approval instance count".into());
        }
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            let name = r.string(128)?;
            if !id(&name) {
                return Err("invalid approved instance".into());
            }
            let phase = match r.take(1)?[0] {
                0 => Phase::Ready,
                1 => Phase::Running,
                2 => Phase::Faulted,
                3 => Phase::Ended,
                4 => Phase::Stopped,
                5 => Phase::Blocked,
                _ => return Err("unknown persisted phase".into()),
            };
            let generation = u64::from_le_bytes(r.take(8)?.try_into().unwrap());
            let restarts = r.number()?;
            if restarts > 32 {
                return Err("invalid persisted restart count".into());
            }
            let waiver = match r.take(1)?[0] {
                0 => None,
                1 => Some(Signature::Unsigned),
                2 => Some(Signature::Invalid),
                _ => return Err("unknown signature waiver".into()),
            };
            let n = r.number()?;
            if n > 256 {
                return Err("permission count exceeds budget".into());
            }
            let mut rights = BTreeMap::new();
            for _ in 0..n {
                let name = r.string(128)?;
                let allow = match r.take(1)?[0] {
                    0 => false,
                    1 => true,
                    _ => return Err("invalid approved permission".into()),
                };
                if !crate::manifest::known_interface(&name) || rights.insert(name, allow).is_some()
                {
                    return Err("unknown or duplicate approved permission".into());
                }
            }
            if entries
                .insert(
                    name,
                    Entry {
                        rights,
                        waiver,
                        phase,
                        generation,
                        restarts,
                    },
                )
                .is_some()
            {
                return Err("duplicate approved instance".into());
            }
        }
        if !r.0.is_empty() {
            return Err("trailing approval data".into());
        }
        Ok(Self {
            binding,
            boot,
            entries,
        })
    }
}
fn boot_id_valid(value: &str) -> bool {
    boot(value)
}

/// One lock and one record for exactly one reviewed deployment. The lock is
/// never inherited across guest exec and is also respected by manual starts.
pub struct Journal {
    directory: File,
    _lock: File,
    record: Option<Record>,
}
fn open_at(directory: &File, name: &std::ffi::CStr, flags: i32) -> std::io::Result<File> {
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
fn private(file: &File, directory: bool) -> Result<()> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    if m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err("state requires exclusive owner and private regular files".into());
    }
    Ok(())
}
impl Journal {
    pub fn open(path: &Path, bundle: &Path) -> Result<Self> {
        crate::verification::protected(path, bundle, true)?;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| e.to_string())?;
        private(&directory, true)?;
        let lock = open_at(&directory, c"lock", libc::O_RDWR | libc::O_CREAT)
            .map_err(|e| e.to_string())?;
        private(&lock, false)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("deployment state is already owned by another supervisor".into());
        }
        let record = match open_at(&directory, c"approval", libc::O_RDONLY) {
            Ok(f) => {
                private(&f, false)?;
                let mut value = Vec::new();
                f.take((MAX_RECORD + 1) as u64)
                    .read_to_end(&mut value)
                    .map_err(|e| e.to_string())?;
                Some(Record::decode(&value)?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string()),
        };
        Ok(Self {
            directory,
            _lock: lock,
            record,
        })
    }
    pub fn check(&self, binding: &str) -> Result<()> {
        if self.record.as_ref().is_none_or(|r| r.binding != binding) {
            return Err("no matching durable approval; operator review is required".into());
        }
        Ok(())
    }
    pub fn existing(&self) -> bool {
        self.record.is_some()
    }
    pub fn entry(&self, name: &str) -> Result<&Entry> {
        self.record
            .as_ref()
            .and_then(|r| r.entries.get(name))
            .ok_or_else(|| "instance has no durable approval".into())
    }
    fn replace(&mut self, next: Record) -> Result<()> {
        let bytes = next.encode()?;
        let mut random = [0u8; 16];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut random))
            .map_err(|e| e.to_string())?;
        let name = std::ffi::CString::new(format!("pending-{:032x}", u128::from_le_bytes(random)))
            .unwrap();
        let mut file = open_at(
            &self.directory,
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )
        .map_err(|e| e.to_string())?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    self.directory.as_raw_fd(),
                    c"approval".as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
            self.directory.sync_all().map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        result?;
        self.record = Some(next);
        Ok(())
    }
    pub fn approve(
        &mut self,
        binding: String,
        boot: String,
        mut entries: BTreeMap<String, Entry>,
    ) -> Result<()> {
        if let Some(old) = &self.record {
            if old.binding != binding || !old.entries.keys().eq(entries.keys()) {
                return Err(
                    "changed deployment requires a separate state directory and operator review"
                        .into(),
                );
            }
            for (name, e) in &mut entries {
                e.generation = old.entries[name].generation;
            }
        }
        self.replace(Record {
            binding,
            boot,
            entries,
        })
    }
    /// A manager crash consumes the same restart budget as a guest crash. A
    /// different kernel boot permits only the explicitly reviewed boot grant.
    /// Normal completion and operator stop never restart in the same boot.
    pub fn resume(&mut self, boot: String, processes: &[&Process]) -> Result<Vec<String>> {
        let mut r = self.record.clone().ok_or("missing durable approval")?;
        let selected = r.resume(boot, processes)?;
        self.replace(r)?;
        Ok(selected)
    }
    pub fn begin(&mut self, name: &str, generation: u64, restart: bool, limit: u32) -> Result<()> {
        let mut r = self.record.clone().ok_or("missing durable approval")?;
        let e = r.entries.get_mut(name).ok_or("unapproved instance")?;
        if generation != e.generation.checked_add(1).ok_or("generation overflow")?
            || if restart {
                e.phase != Phase::Faulted || e.restarts >= limit
            } else {
                e.phase != Phase::Ready
            }
        {
            return Err("durable start transition denied".into());
        }
        if restart {
            e.restarts += 1;
        }
        e.generation = generation;
        e.phase = Phase::Running;
        self.replace(r)
    }
    pub fn exited(&mut self, name: &str, success: bool) -> Result<()> {
        let mut r = self.record.clone().ok_or("missing durable approval")?;
        let e = r.entries.get_mut(name).ok_or("unapproved instance")?;
        if e.phase != Phase::Running {
            return Err("unexpected durable exit transition".into());
        }
        e.phase = if success {
            Phase::Ended
        } else {
            Phase::Faulted
        };
        self.replace(r)
    }
    pub fn stop(&mut self, blocked: bool) -> Result<()> {
        let mut r = self.record.clone().ok_or("missing durable approval")?;
        for e in r.entries.values_mut() {
            e.phase = if blocked {
                Phase::Blocked
            } else {
                Phase::Stopped
            };
        }
        self.replace(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Record {
        Record {
            binding: "a".repeat(64),
            boot: "00000000-0000-0000-0000-000000000001".into(),
            entries: BTreeMap::from([(
                "body".into(),
                Entry::reviewed(BTreeMap::from([("abi".into(), true)]), None),
            )]),
        }
    }
    fn process(restart: bool, start: bool, limit: u32) -> Process {
        crate::manifest::deployment(&format!("<deployment id=\"cell\"><vm id=\"body\" module=\"body.wasm\" sha256=\"{}\" policy=\"body.policy\" memory-bytes=\"1024\" pids=\"4\" restart-on-crash=\"{}\" start-on-boot=\"{}\" restart-limit=\"{}\"/></deployment>","a".repeat(64),restart,start,limit)).unwrap().processes.remove(0)
    }
    #[test]
    fn manager_crashes_cannot_reset_approved_retry_budget() {
        let mut r = sample();
        let p = process(true, false, 2);
        let boot = r.boot.clone();
        assert_eq!(r.resume(boot.clone(), &[&p]).unwrap(), vec!["body"]);
        assert_eq!(r.entries["body"].restarts, 1);
        let bytes = r.encode().unwrap();
        let mut r = Record::decode(&bytes).unwrap();
        assert_eq!(r.resume(boot.clone(), &[&p]).unwrap(), vec!["body"]);
        assert_eq!(r.entries["body"].restarts, 2);
        assert!(r.resume(boot, &[&p]).unwrap().is_empty());
        assert_eq!(r.entries["body"].phase, Phase::Blocked);
    }
    #[test]
    fn stop_and_completion_are_distinct_from_crash_and_reboot() {
        for phase in [Phase::Ended, Phase::Stopped, Phase::Blocked] {
            let mut r = sample();
            let p = process(true, true, 3);
            r.entries.get_mut("body").unwrap().phase = phase;
            assert!(r.resume(r.boot.clone(), &[&p]).unwrap().is_empty());
            // A boot grant authorizes a fresh cold start even after an earlier
            // manual stop. It never reconstructs application or motion state.
            assert_eq!(
                r.resume("00000000-0000-0000-0000-000000000002".into(), &[&p])
                    .unwrap(),
                vec!["body"]
            );
            assert_eq!(r.entries["body"].restarts, 0);
        }
        let mut r = sample();
        let p = process(true, false, 3);
        assert!(r
            .resume("00000000-0000-0000-0000-000000000002".into(), &[&p])
            .unwrap()
            .is_empty());
        let mut r = sample();
        let p = process(false, false, 3);
        assert!(r.resume(r.boot.clone(), &[&p]).unwrap().is_empty());
    }
    #[test]
    fn automatic_resume_cannot_add_instances_or_authority() {
        let mut r = sample();
        let mut p = process(true, true, 3);
        p.id = "other".into();
        assert!(r.resume(r.boot.clone(), &[&p]).is_err());
        assert!(r.resume(r.boot.clone(), &[]).is_err());
        let p = process(true, true, 3);
        let original = r.entries["body"].rights.clone();
        r.resume(r.boot.clone(), &[&p]).unwrap();
        assert_eq!(original, r.entries["body"].rights);
    }
    #[test]
    fn bounded_record_rejects_corruption_and_unknown_authority() {
        let r = sample();
        let bytes = r.encode().unwrap();
        assert_eq!(
            Record::decode(&bytes).unwrap().entries["body"].rights["abi"],
            true
        );
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(Record::decode(&bad).is_err());
        }
        let mut bad = sample();
        bad.entries
            .get_mut("body")
            .unwrap()
            .rights
            .insert("unregistered.operation".into(), true);
        assert!(bad.encode().is_err());
        let mut bad = sample();
        bad.entries.get_mut("body").unwrap().waiver = Some(Signature::Verified);
        assert!(bad.encode().is_err());
        assert!(Record::decode(&vec![0; MAX_RECORD + 1]).is_err());
    }
}
