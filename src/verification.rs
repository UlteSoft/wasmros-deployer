//! First-stage offline WSEA admission on the exact reviewed Wasm bytes.
use crate::manifest::Result;
use crate::verdict::Signature;
use std::os::fd::AsRawFd;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_MODULE: u64 = 256 * 1024 * 1024;
const VERIFY_TIMEOUT: Duration = Duration::from_secs(30);

/// Check the operator-supplied roots and the binary before executing any code.
/// Paths of submitted modules are never accepted as the verifier or policy store.
fn protected(path: &Path, bundle: &Path, directory: bool) -> Result<PathBuf> {
    let real = path.canonicalize().map_err(|e| e.to_string())?;
    if !path.is_absolute() || real != path || real.starts_with(bundle) {
        return Err(format!("expected a protected absolute path outside the bundle: {path:?}"));
    }
    let uid = unsafe { libc::geteuid() };
    for ancestor in real.ancestors() {
        let info = fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        let sticky = ancestor != real && info.is_dir() && info.uid() == 0 && info.mode() & 0o1000 != 0;
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

struct Snapshot(PathBuf);
impl Drop for Snapshot {
    fn drop(&mut self) { let _ = fs::remove_file(&self.0); }
}

fn create_snapshot(scratch: &Path, mut input: File, digest: &str) -> Result<Snapshot> {
    let mut random = [0u8; 16];
    File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut random)).map_err(|e| e.to_string())?;
    let path = scratch.join(format!("module-{:032x}.wasm", u128::from_le_bytes(random)));
    let mut copy = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&path).map_err(|e| e.to_string())?;
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
        if n == 0 { break; }
        total += n as u64;
        if total > MAX_MODULE { return Err("module exceeds the verification limit".into()); }
        hash.update(&buf[..n]);
        copy.write_all(&buf[..n]).map_err(|e| e.to_string())?;
    }
    if format!("{:x}", hash.finalize()) != digest { return Err("module snapshot digest mismatch".into()); }
    Ok(snapshot)
}

/// Verify the bytes copied into a private directory, with bounded size and time.
/// Success is an observation during preflight. Execution still requires VM verification.
pub fn verify(verifier: &Path, scratch: &Path, bundle: &Path, module: File,
              digest: &str, trust: &Path) -> Result<Signature> {
    let verifier = protected(verifier, bundle, false)?;
    let trust = protected(trust, bundle, false)?;
    let scratch = protected(scratch, bundle, true)?;
    let info = fs::metadata(&scratch).map_err(|e| e.to_string())?;
    if info.mode() & 0o777 != 0o700 || info.uid() != unsafe { libc::geteuid() } {
        return Err("verification scratch must be a private directory owned by the operator".into());
    }
    let snapshot = create_snapshot(&scratch, module, digest)?;
    let mut cmd = Command::new(verifier);
    cmd.args(["wasm", "secure", "verify"]).arg(&snapshot.0).arg("--policy").arg(trust)
        .env_clear().stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    println!("INFO Executing verifier {:?} {:?}", cmd.get_program(), cmd.get_args().collect::<Vec<_>>());
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let end = Instant::now() + VERIFY_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(Signature::Verified),
            Ok(Some(status)) => {
                if status.code() != Some(1) { return Err(format!("verifier failed ({status})")); }
                // The trusted verifier has exited. Bound the diagnostic and refuse
                // incomplete output if a descendant still holds the writing end.
                let pipe = child.stderr.take().ok_or("missing verifier diagnostic")?;
                let fd = pipe.as_raw_fd();
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
                    return Err("could not bound the verifier diagnostic".into());
                }
                let mut reason = Vec::with_capacity(4097);
                pipe.take(4097).read_to_end(&mut reason).map_err(|e| e.to_string())?;
                if reason.len() > 4096 { return Err("verifier diagnostic exceeds limit".into()); }
                eprintln!("Verifier rejection: {:?}", String::from_utf8_lossy(&reason));
                return Signature::rejected(&reason).ok_or_else(|| "unclassified verification, trust or policy failure".into());
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
