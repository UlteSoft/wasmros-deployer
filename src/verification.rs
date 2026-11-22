//! First-stage offline WSEA admission on the exact reviewed Wasm bytes.
use crate::manifest::{local_file, DriverArtifact, Result};
use crate::verdict::Signature;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::manifest::libraries::MAX_IMAGE_BYTES as MAX_MODULE;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// Check the operator-supplied roots and the binary before executing any code.
/// Paths of submitted modules are never accepted as the verifier or policy store.
pub fn protected(path: &Path, bundle: &Path, directory: bool) -> Result<PathBuf> {
    let real = protected_path(path, directory)?;
    if real.starts_with(bundle) {
        return Err(format!("expected a protected path outside the bundle: {path:?}"));
    }
    Ok(real)
}

/// Check a locally configured path whose caller does not consume a bundle.
pub(crate) fn protected_path(path: &Path, directory: bool) -> Result<PathBuf> {
    let real = path.canonicalize().map_err(|e| e.to_string())?;
    if !path.is_absolute() || real != path {
        return Err(format!("expected a protected absolute path: {path:?}"));
    }
    let uid = unsafe { libc::geteuid() };
    for ancestor in real.ancestors() {
        let info = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        let sticky =
            ancestor != real && info.is_dir() && info.uid() == 0 && info.mode() & 0o1000 != 0;
        if !(info.uid() == 0 || info.uid() == uid) || (info.mode() & 0o022 != 0 && !sticky) {
            return Err(format!("untrusted permissions or owner: {ancestor:?}"));
        }
    }
    let info = fs::metadata(&real).map_err(|e| e.to_string())?;
    if directory && !info.is_dir() || !directory && (!info.is_file() || info.nlink() != 1) {
        return Err(format!("unexpected protected file type: {real:?}"));
    }
    Ok(real)
}

pub fn policy(root: &Path, relative: &Path, bundle: &Path) -> Result<PathBuf> {
    let root = protected(root, bundle, true)?;
    let file = root.join(relative);
    if !file.starts_with(&root) {
        return Err("policy escaped its protected root".into());
    }
    protected(&file, bundle, false)
}

/// Resolve the protected CA file independently of the writable rollback store.
pub fn policy_trust_root(policy: &Path, bundle: &Path) -> Result<PathBuf> {
    let text = crate::manifest::xml_contents(crate::manifest::open_regular(policy, crate::manifest::MAX_XML)?)?;
    let mut fields = text.lines().filter_map(|line| line.strip_prefix("trust_root="));
    let path = fields.next().ok_or("missing WSEA trust root")?;
    if fields.next().is_some() { return Err("duplicate WSEA trust root".into()); }
    protected(Path::new(path), bundle, false)
}

/// Privileged admission and the unprivileged VM keep independent anti-rollback
/// stores. Only state_dir may differ; signature algorithms, trust and all module
/// authorization rules must be byte-for-byte identical. VM's protected-path
/// verifier continues to reopen this administrator-owned policy itself.
pub fn equivalent_vm_policy(primary: &Path, secondary: &Path) -> Result<()> {
    fn rules(path: &Path) -> Result<(Vec<String>, String)> {
        let text = crate::manifest::xml_contents(File::open(path).map_err(|e| e.to_string())?)?;
        let mut rules = Vec::new();
        let mut state = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("state_dir=") {
                if !value.starts_with('/') || state.replace(value.to_owned()).is_some() {
                    return Err("invalid policy state directory".into());
                }
            } else {
                rules.push(line.to_owned());
            }
        }
        Ok((rules, state.ok_or("missing policy state directory")?))
    }
    let (a, sa) = rules(primary)?;
    let (b, sb) = rules(secondary)?;
    if a != b || sa == sb {
        return Err(
            "VM policy must preserve all trust rules and use a separate state directory".into(),
        );
    }
    Ok(())
}

struct Snapshot(PathBuf);
impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn create_snapshot(scratch: &Path, mut input: File, digest: &str, suffix: &str) -> Result<Snapshot> {
    let mut random = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut random))
        .map_err(|e| e.to_string())?;
    let path = scratch.join(format!("image-{:032x}.{suffix}", u128::from_le_bytes(random)));
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let snapshot = Snapshot(path);
    let info = input.metadata().map_err(|e| e.to_string())?;
    if !info.is_file() || info.len() > MAX_MODULE {
        return Err("invalid module type or size".into());
    }
    let mut total = 0u64;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 32768];
    loop {
        let n = input.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_MODULE {
            return Err("module exceeds the verification limit".into());
        }
        hash.update(&buf[..n]);
        copy.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    }
    if format!("{:x}", hash.finalize()) != digest {
        return Err("module snapshot digest mismatch".into());
    }
    Ok(snapshot)
}

/// Verify the bytes copied into a private directory, with bounded size and time.
/// Success is an observation during preflight. Execution still requires VM verification.
pub fn verify(
    verifier: &Path,
    scratch: &Path,
    bundle: &Path,
    module: File,
    digest: &str,
    trust: &Path,
) -> Result<Signature> {
    Ok(admit(verifier, scratch, bundle, module, digest, trust)?.signature)
}

/// Sealed bytes are inherited by the VM. Neither source replacement after review
/// nor a writable input descriptor can change the image between admission and exec.
pub struct FrozenFile(pub File);
impl FrozenFile {
    pub fn copy(mut source: File, limit: u64, expected: Option<&str>) -> Result<Self> {
        Self::copy_with(&mut source, limit, expected, false)
    }

    fn copy_with(mut source: impl Read, limit: u64, expected: Option<&str>, elf: bool) -> Result<Self> {
        let name = std::ffi::CString::new("wros-admitted").unwrap();
        let mut flags = libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC;
        if elf {
            flags |= libc::MFD_EXEC;
        }
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), flags)
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut target = unsafe { File::from_raw_fd(fd) };
        let mut hash = Sha256::new();
        let mut total = 0u64;
        let mut buf = [0u8; 32768];
        loop {
            let n = source.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total = total
                .checked_add(n as u64)
                .ok_or("snapshot size overflow")?;
            if total > limit {
                return Err("snapshot exceeds byte budget".into());
            }
            hash.update(&buf[..n]);
            target.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        }
        if expected.is_some_and(|e| e != format!("{:x}", hash.finalize())) {
            return Err("immutable snapshot digest mismatch".into());
        }
        let mut seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if elf {
            if unsafe { libc::fchmod(fd, 0o555) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            seals |= libc::F_SEAL_EXEC;
        }
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if elf {
            target = File::open(format!("/proc/self/fd/{fd}")).map_err(|e| e.to_string())?;
            target = crate::supervisor::retained(target)?;
        }
        Ok(Self(target))
    }
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.0.as_raw_fd()))
    }
}

/// Read the exact declared module for a non-executing review without granting
/// authority. The signature verifier remains required for deployment.
pub fn snapshot_for_review(file: File, expected: &str) -> Result<FrozenFile> {
    FrozenFile::copy(file, MAX_MODULE, Some(expected))
}
pub struct Admission {
    pub module: FrozenFile,
    pub signature: Signature,
}

pub fn admit(
    verifier: &Path,
    scratch: &Path,
    bundle: &Path,
    module: File,
    digest: &str,
    trust: &Path,
) -> Result<Admission> {
    admit_image(verifier, scratch, bundle, module, digest, trust, None)
}

/// The named form additionally requires the trusted CLI's authenticated WSEA
/// identity receipt. Exit success alone can describe a different authorized
/// publisher/module pair when a policy contains multiple rules.
pub fn admit_image(
    verifier: &Path,
    scratch: &Path,
    bundle: &Path,
    module: File,
    digest: &str,
    trust: &Path,
    expected_id: Option<&str>,
) -> Result<Admission> {
    let verifier = protected(verifier, bundle, false)?;
    let trust = protected(trust, bundle, false)?;
    let scratch = private_scratch(scratch, bundle)?;
    let snapshot = create_snapshot(&scratch, module, digest, "wasm")?;
    let signature = check_signature(&verifier, &snapshot.0, &trust, expected_id)?;
    let module = FrozenFile::copy(
        File::open(&snapshot.0).map_err(|e| e.to_string())?,
        MAX_MODULE,
        Some(digest),
    )?;
    Ok(Admission { module, signature })
}

fn private_scratch(scratch: &Path, bundle: &Path) -> Result<PathBuf> {
    let scratch = protected(scratch, bundle, true)?;
    let info = fs::metadata(&scratch).map_err(|e| e.to_string())?;
    if info.mode() & 0o777 != 0o700 || info.uid() != unsafe { libc::geteuid() } {
        return Err(
            "verification scratch must be a private directory owned by the operator".into(),
        );
    }
    Ok(scratch)
}

/// Check the same appended CMS envelope used by the VM's native verifier,
/// using its offline command. This path does not load or execute the ELF.
pub fn verify_driver(
    verifier: &Path,
    scratch: &Path,
    bundle: &Path,
    directory: &File,
    policies: &Path,
    driver: &DriverArtifact,
) -> Result<Signature> {
    let verifier = protected(verifier, bundle, false)?;
    let signer = driver.elf_signer.as_ref().ok_or("missing ELF signer policy")?;
    let signer = policy(policies, signer, bundle)?;
    let scratch = private_scratch(scratch, bundle)?;
    let snapshot = create_snapshot(
        &scratch,
        local_file(directory, &driver.file)?,
        &driver.digest,
        "elf",
    )?;
    let mut cmd = Command::new(verifier);
    cmd.arg("--verify-elf-driver")
        .arg(&driver.kind)
        .arg(&snapshot.0)
        .arg(signer);
    verify_with(cmd, elf_outcome, true)
}

fn elf_outcome(status: ExitStatus, reason: &[u8]) -> Option<Signature> {
    match (status.code(), reason) {
        (Some(2), b"ELF verification: driver has no Linux appended module signature\n") => Some(Signature::Unsigned),
        (Some(3), b"ELF verification: driver signature invalid or signer is not the host-pinned certificate\n") => Some(Signature::Invalid),
        _ => None,
    }
}

/// Exact launch bytes and the trusted verifier selected during initial admission.
pub struct NativeAdmission {
    pub(crate) image: FrozenFile,
    verifier: File,
    signer: PathBuf,
    signer_digest: String,
    bundle: PathBuf,
    verdict: Signature,
}

impl NativeAdmission {
    pub fn prepare(
        verifier: &Path,
        bundle: &Path,
        directory: &File,
        policies: &Path,
        driver: &DriverArtifact,
        exception: Option<Signature>,
    ) -> Result<Self> {
        if driver.kind != "executable" {
            return Err("native launch requires an ELF executable".into());
        }
        let path = protected(verifier, bundle, false)?;
        let verifier = crate::supervisor::retained(File::open(path).map_err(|e| e.to_string())?)?;
        let signer = policy(policies, driver.elf_signer.as_ref().ok_or("missing ELF signer policy")?, bundle)?;
        let signer_digest = crate::manifest::sha256(crate::manifest::open_regular(&signer, crate::manifest::MAX_XML)?)?;
        let image = FrozenFile::copy_with(local_file(directory, &driver.file)?, MAX_MODULE, Some(&driver.digest), true)?;
        let mut admitted = Self { image, verifier, signer, signer_digest, bundle: bundle.into(), verdict: Signature::Verified };
        let verdict = admitted.verify(true)?;
        if verdict != Signature::Verified && exception != Some(verdict) {
            return Err(format!("{verdict:?} ELF signature rejected for {:?}", driver.id));
        }
        admitted.verdict = verdict;
        Ok(admitted)
    }

    pub fn verdict(&self) -> Signature {
        self.verdict
    }

    pub(crate) fn reverify(&self) -> Result<()> {
        if self.verify(false)? != self.verdict {
            return Err("ELF verification outcome changed after review".into());
        }
        Ok(())
    }

    fn verify(&self, audit: bool) -> Result<Signature> {
        let signer = protected(&self.signer, &self.bundle, false)?;
        let signer = FrozenFile::copy(
            crate::manifest::open_regular(&signer, crate::manifest::MAX_XML)?,
            crate::manifest::MAX_XML,
            Some(&self.signer_digest),
        )?;
        let signer = FrozenFile(crate::supervisor::retained(signer.0)?);
        let verifier = self.verifier.as_raw_fd();
        let image = self.image.0.as_raw_fd();
        let certificate = signer.0.as_raw_fd();
        let mut cmd = Command::new(format!("/proc/self/fd/{verifier}"));
        cmd.arg("--verify-elf-driver").arg("executable").arg(self.image.path()).arg(signer.path());
        // The verifier opens the sealed image and PEM through inherited handles.
        unsafe {
            cmd.pre_exec(move || {
                for fd in [image, certificate] {
                    if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        verify_with(cmd, elf_outcome, audit)
    }
}

fn check_signature(verifier: &Path, snapshot: &Path, trust: &Path, expected_id: Option<&str>) -> Result<Signature> {
    let mut cmd = Command::new(verifier);
    cmd.args(["wasm", "secure", "verify"])
        .arg(snapshot)
        .arg("--policy")
        .arg(trust);
    verify_with_receipt(cmd, |status, reason| {
        if status.code() == Some(1) {
            Signature::rejected(reason)
        } else {
            None
        }
    }, true, expected_id)
}

fn verify_with(
    cmd: Command,
    classify: impl Fn(ExitStatus, &[u8]) -> Option<Signature>,
    audit: bool,
) -> Result<Signature> {
    verify_with_receipt(cmd, classify, audit, None)
}

// This is the canonical stdout record of cosign's wasm secure verify command
// (Go json.Encoder over its fixed output and wasmsecure.Manifest structs).
// Match complete fields at the known position. A changed wire format closes
// admission; arbitrary strings elsewhere in the manifest cannot select an ID.
fn named_receipt(record: &[u8], id: &str) -> bool {
    if !crate::manifest::libraries::identifier(id) || !record.ends_with(b"}}\n") { return false; }
    let Some(record) = record.strip_prefix(br#"{"status":"VERIFIED","manifest":{"embedded":true,"algorithm":""#) else { return false; };
    let Some(end) = record.iter().position(|&c| c == b'"') else { return false; };
    if end == 0 || !record[..end].iter().all(u8::is_ascii_alphanumeric) { return false; }
    let Some(record) = record[end..].strip_prefix(br#"","module_id":""#) else { return false; };
    record.strip_prefix(id.as_bytes()).is_some_and(|rest| rest.starts_with(br#"","version":"#))
}

fn read_verifier_pipe(pipe: impl Read + AsRawFd, description: &str) -> Result<Vec<u8>> {
    // A descendant may retain a pipe after the trusted verifier has exited.
    let fd = pipe.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(format!("could not bound {description}"));
    }
    let mut output = Vec::with_capacity(4097);
    pipe.take(4097).read_to_end(&mut output).map_err(|e| e.to_string())?;
    if output.len() > 4096 { return Err(format!("{description} exceeds limit")); }
    Ok(output)
}

fn verify_with_receipt(
    mut cmd: Command,
    classify: impl Fn(ExitStatus, &[u8]) -> Option<Signature>,
    audit: bool,
    expected_id: Option<&str>,
) -> Result<Signature> {
    cmd.env_clear()
        .stdin(Stdio::null())
        .stdout(if expected_id.is_some() { Stdio::piped() } else { Stdio::null() })
        .stderr(Stdio::piped());
    if audit { println!(
        "INFO Executing verifier {:?} {:?}",
        cmd.get_program(),
        cmd.get_args().collect::<Vec<_>>()
    ); }
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let end = Instant::now() + VERIFY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => {
                if let Some(id) = expected_id {
                    let pipe = child.stdout.take().ok_or("missing named WSEA receipt")?;
                    let receipt = read_verifier_pipe(pipe, "named WSEA receipt")?;
                    if !named_receipt(&receipt, id) {
                        return Err(format!("verified WSEA identity does not match declared module-id {id:?}"));
                    }
                }
                return Ok(Signature::Verified);
            }
            Ok(Some(status)) => {
                let pipe = child.stderr.take().ok_or("missing verifier diagnostic")?;
                let reason = read_verifier_pipe(pipe, "verifier diagnostic")?;
                if audit {
                    eprintln!("Verifier rejection: {:?}", String::from_utf8_lossy(&reason));
                }
                return classify(status, &reason)
                    .ok_or_else(|| format!("unclassified verification, trust or policy failure: {:?}", String::from_utf8_lossy(&reason)));
            }
            Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(5)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("verifier interrupted or timed out: {other:?}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_image_descriptor_is_read_only_with_sealed_executable_mode() {
        let image = FrozenFile::copy_with(&b"fixture"[..], 64, None, true).unwrap();
        let fd = image.0.as_raw_fd();
        let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        assert!(seals >= 0 && seals & libc::F_SEAL_EXEC != 0 && seals & libc::F_SEAL_WRITE != 0);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE, libc::O_RDONLY);
        assert_eq!(image.0.metadata().unwrap().mode() & 0o777, 0o555);
        assert_ne!(unsafe { libc::fchmod(fd, 0o544) }, 0);
        assert_eq!(image.0.metadata().unwrap().mode() & 0o777, 0o555);
    }

    #[test]
    fn admitted_memory_cannot_be_mutated_or_resized() {
        let source = File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
        let frozen = FrozenFile::copy(source, 65536, None).unwrap();
        let fd = frozen.0.as_raw_fd();
        assert_eq!(unsafe { libc::pwrite(fd, b"x".as_ptr().cast(), 1, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(unsafe { libc::ftruncate(fd, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert!(FrozenFile::copy(
            File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap(),
            1,
            None
        )
        .is_err());
        assert!(FrozenFile::copy(
            File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap(),
            65536,
            Some(&"0".repeat(64))
        )
        .is_err());
    }
}
