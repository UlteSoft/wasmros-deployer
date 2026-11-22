//! Query the operator-selected executable's built-in host catalogue without loading Wasm.
use crate::manifest::{Permission, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::FileExt, process::CommandExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Features { ros1: bool, ros2: bool, wasi64: bool }
impl Features {
    /// Ordinary ROSv2 and Preview 1 clocks are part of the managed product profile.
    /// These optional build switches also affect whether the generated CLI is accepted.
    fn optional(key: &str) -> bool {
        matches!(Permission::from_key(key), Some(Permission::LegacyRosAbi { .. }))
            || matches!(Permission::from_key(key), Some(Permission::ClockInterface(name)) if name.ends_with("_wasm64"))
    }

    fn parse(report: &[u8]) -> Self {
        let has = |expected: &[u8]| report.split(|byte| *byte == b'\n').any(|line| line.trim_ascii() == expected);
        Self {
            ros1: has(b"* Deprecated ROSv1 imports for ROS 1 (explicit build opt-in)"),
            ros2: has(b"* Deprecated ROSv1 imports for ROS 2 (explicit build opt-in)"),
            wasi64: has(b"* Support Imported WASI Preview 1 (With WASM64 Extension)"),
        }
    }

    pub fn unsupported(&self, key: &str) -> bool {
        match Permission::from_key(key) {
            Some(Permission::LegacyRosAbi { host, .. }) => if host == "ros1" { !self.ros1 } else { !self.ros2 },
            Some(Permission::ClockInterface(name)) => name.ends_with("_wasm64") && !self.wasi64,
            _ => false,
        }
    }

    /// The probe has no deployment arguments, guest images, inherited authority, or
    /// bundle working directory. Its private output and elapsed time are bounded.
    pub fn inspect(runtime: &Path, bundle: &Path) -> Result<Self> {
        let path = crate::verification::protected(runtime, bundle, false)?;
        let image = crate::supervisor::retained(File::open(path).map_err(|e| e.to_string())?)?;
        let mut magic = [0; 2];
        image.read_exact_at(&mut magic, 0).map_err(|e| e.to_string())?;
        let fd = image.as_raw_fd();
        let output = unsafe { libc::memfd_create(c"wros-runtime-features".as_ptr(), libc::MFD_CLOEXEC) };
        if output < 0 { return Err(std::io::Error::last_os_error().to_string()); }
        let output = unsafe { File::from_raw_fd(output) };
        let clone = || output.try_clone().map(Stdio::from).map_err(|e| e.to_string());
        let mut cmd = Command::new(format!("/proc/self/fd/{fd}"));
        cmd.args(["--log-color", "disable", "--version"]).current_dir("/").env_clear()
            .stdin(Stdio::null()).stdout(clone()?).stderr(clone()?);
        if unsafe { libc::geteuid() } == 0 { cmd.uid(65534).gid(65534); }
        const MAX: u64 = 65536;
        unsafe {
            cmd.pre_exec(move || {
                let cap = libc::rlimit { rlim_cur: MAX as _, rlim_max: MAX as _ };
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
                    libc::setrlimit(libc::RLIMIT_FSIZE, &cap) < 0 ||
                    libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, libc::CLOSE_RANGE_CLOEXEC) < 0 ||
                    magic == *b"#!" && libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().map_err(|e| format!("could not query the selected VM build: {e}"))?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => break,
                Ok(Some(status)) => return Err(format!("selected VM build report failed: {status}")),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
                other => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("selected VM build report interrupted or timed out: {other:?}"));
                }
            }
        }
        let length = output.metadata().map_err(|e| e.to_string())?.len();
        if length >= MAX { return Err("selected VM build report exceeds its byte budget".into()); }
        let mut data = vec![0; length as usize];
        output.read_exact_at(&mut data, 0).map_err(|e| e.to_string())?;
        Ok(Self::parse(&data))
    }
}

/// An offline review may omit the executable. Managed execution always supplies
/// the protected, digest-bound runtime. Probe once, only for optional features.
pub struct Check<'a> {
    pub runtime: Option<&'a Path>,
    pub bundle: &'a Path,
    pub features: Option<Features>,
}

impl Check<'_> {
    pub fn assess(&mut self, inventory: &crate::guest_imports::ImportAssessment, requires: &BTreeSet<String>,
                  rights: &BTreeMap<String, bool>) -> Result<crate::import_permissions::Assessment> {
        let mut result = crate::import_permissions::assess(inventory, requires, rights);
        let crate::guest_imports::ImportAssessment::Complete { imports } = inventory else { return Ok(result); };
        let imported: BTreeSet<_> = imports.iter().filter_map(|(ns, name)| match ns.as_str() {
            "uwvm_ros1_v1" | "uwvm_ros2_v1" => Some(format!("{ns}.{name}")),
            "wasi_snapshot_preview1" if name.ends_with("_wasm64") => Some(format!("wasip1.{name}")),
            _ => None,
        }).collect();
        // Legacy CLI flags themselves are compiled out with the ABI. Preview 1
        // accepts a wasm64 catalogue rule even on a wasm32-only provider, so
        // that extension is required only by a real import of its wrapper.
        let legacy_settings = rights.keys().filter(|key| matches!(Permission::from_key(key), Some(Permission::LegacyRosAbi { .. })));
        let selected: BTreeSet<_> = imported.iter().filter(|key| Features::optional(key)).chain(legacy_settings).collect();
        if !selected.is_empty() {
            if let Some(runtime) = self.runtime {
                if self.features.is_none() { self.features = Some(Features::inspect(runtime, self.bundle)?); }
                for key in selected {
                    if self.features.as_ref().unwrap().unsupported(key) {
                        if imported.contains(key) {
                            result.immutable_blocker = true;
                            result.blocked.push(format!("selected VM build lacks the provider for imported {key:?}; select a build with this host ABI"));
                        } else {
                            result.blocked.push(format!("selected VM build cannot configure {key:?}; enter 'remove {key}' or select a build with this host ABI"));
                        }
                    }
                }
            } else {
                result.warnings.push(format!("optional host interfaces {selected:?} require a matching VM build; supply --runtime EXECUTABLE to check the build during preflight"));
            }
        }
        Ok(result)
    }
}
