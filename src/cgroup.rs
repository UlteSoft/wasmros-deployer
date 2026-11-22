//! Deployment-owned cgroup v2 hierarchy. VM children receive only a one-use
//! enrollment descriptor, closed by exec; they never receive directory handles.
//! The operator must supply an empty, bounded, root-owned delegated subtree with
//! cpu, memory and pids already enabled. This module never changes its ancestors.
use crate::manifest::{DriverArtifact, Process, Result};
use crate::placement::Set;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

fn error() -> String {
    std::io::Error::last_os_error().to_string()
}
fn component(name: &str) -> Result<CString> {
    if name.is_empty()
        || name.len() > 160
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        || name == "."
        || name == ".."
    {
        return Err("invalid cgroup component".into());
    }
    CString::new(name).map_err(|e| e.to_string())
}
pub(crate) fn open_at(parent: &File, name: &str, flags: i32) -> Result<File> {
    let name = component(name)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
pub(crate) fn read(parent: &File, name: &str) -> Result<String> {
    let mut value = String::new();
    open_at(parent, name, libc::O_RDONLY)?
        .take(8193)
        .read_to_string(&mut value)
        .map_err(|e| e.to_string())?;
    if value.len() > 8192 {
        return Err("cgroup state exceeds budget".into());
    }
    Ok(value)
}
pub(crate) fn write(parent: &File, name: &str, value: &str) -> Result<()> {
    let mut file = open_at(parent, name, libc::O_WRONLY)?;
    // A cgroup operation is one write, not a stream of partial commands.
    if file.write(value.as_bytes()).map_err(|e| e.to_string())? != value.len() {
        return Err("incomplete cgroup operation".into());
    }
    Ok(())
}
pub(crate) fn owner(file: &File) -> Result<()> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("cgroup must be a root-owned, non-writable directory for guests".into());
    }
    Ok(())
}

pub struct Group {
    directory: File,
    parent: File,
    name: CString,
}
impl Group {
    fn create(parent: &File, name: &str) -> Result<Self> {
        let component = component(name)?;
        let parent = parent.try_clone().map_err(|e| e.to_string())?;
        if unsafe { libc::mkdirat(parent.as_raw_fd(), component.as_ptr(), 0o755) } != 0 {
            return Err(format!(
                "cgroup already exists or cannot be created ({name}): {}",
                error()
            ));
        }
        let directory = match open_at(&parent, name, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(dir) => dir,
            Err(e) => {
                unsafe {
                    libc::unlinkat(parent.as_raw_fd(), component.as_ptr(), libc::AT_REMOVEDIR);
                };
                return Err(e);
            }
        };
        let group = Self {
            directory,
            parent,
            name: component,
        };
        owner(&group.directory)?;
        Ok(group)
    }
    pub fn enrollment(&self) -> Result<File> {
        open_at(&self.directory, "cgroup.procs", libc::O_WRONLY)
    }
    /// Detect unavailable/offlined resources again immediately before each
    /// generation starts. A requested set must be effective in full, not just
    /// intersect with the parent's allocation. Runtime hotplug may still change
    /// the effective set; hardware safety must not depend on placement alone.
    pub fn verify_placement(&self, process: &Process) -> Result<()> {
        self.verify_sets(process.cpus.as_ref(), process.memory_nodes.as_ref())
    }

    fn verify_sets(&self, cpus: Option<&Set>, memory_nodes: Option<&Set>) -> Result<()> {
        for (name, requested) in [
            ("cpuset.cpus.effective", cpus),
            ("cpuset.mems.effective", memory_nodes),
        ] {
            if let Some(requested) = requested {
                if &Set::parse(read(&self.directory, name)?.trim())? != requested {
                    return Err(format!(
                        "effective {name} differs from the reviewed placement"
                    ));
                }
            }
        }
        Ok(())
    }
    pub fn accounting(&self) -> Result<String> {
        Ok(format!(
            "memory: {}; tasks: {}",
            read(&self.directory, "memory.events")?
                .trim()
                .replace('\n', ", "),
            read(&self.directory, "pids.events")?
                .trim()
                .replace('\n', ", ")
        ))
    }
    pub fn kill(&self) -> Result<()> {
        write(&self.directory, "cgroup.kill", "1")
    }
    pub fn empty(&self) -> Result<bool> {
        let events = read(&self.directory, "cgroup.events")?;
        match events.lines().find_map(|l| l.strip_prefix("populated ")) {
            Some("0") => Ok(true),
            Some("1") => Ok(false),
            _ => Err("invalid cgroup populated state".into()),
        }
    }
    /// A new generation may start only after all descendants of the old one exit.
    pub fn drain(&self, timeout: Duration) -> Result<()> {
        self.kill()?;
        let deadline = Instant::now() + timeout;
        while !self.empty()? {
            if Instant::now() >= deadline {
                return Err("cgroup remains populated; restart forbidden".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        // Best effort on exceptional unwinding. The explicit normal path checks
        // drain and reports failures. The ultimate service supervisor remains
        // responsible if the deployer is killed or a kernel task cannot exit.
        let _ = self.kill();
        unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            );
        }
    }
}

pub(crate) fn directory(path: &Path) -> Result<File> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("run requires a privileged deployment supervisor; guests use distinct unprivileged identities".into());
    }
    if !path.is_absolute()
        || path.canonicalize().map_err(|e| e.to_string())? != path
        || path == Path::new("/sys/fs/cgroup")
    {
        return Err("supply an explicit delegated cgroup subtree".into());
    }
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    owner(&parent)?;
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(parent.as_raw_fd(), &mut stat) } != 0
        || stat.f_type as u64 != 0x63677270
    {
        return Err("expected cgroup v2 filesystem".into());
    }
    Ok(parent)
}

pub(crate) fn delegated_parent(path: &Path) -> Result<File> {
    let parent = directory(path)?;
    if !read(&parent, "cgroup.procs")?.trim().is_empty()
        || read(&parent, "cgroup.type")?.trim() != "domain"
    {
        return Err("delegated parent must be an empty domain cgroup".into());
    }
    Ok(parent)
}

/// Approval never kills existing work. A missing future service directory is
/// acceptable, but an existing service must be entirely inactive before review
/// can replace its authority. The independent supervisor owns that directory.
pub fn require_inactive(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
        Ok(_) => {
            let group = directory(path)?;
            if !read(&group, "cgroup.events")?
                .lines()
                .any(|s| s == "populated 0")
            {
                return Err("approval requires an inactive supervisor cgroup".into());
            }
            Ok(())
        }
    }
}

pub struct Hierarchy {
    pub children: Vec<Group>,
    root: Group,
}

pub(crate) struct Workload<'a> {
    name: String,
    identity: Option<(u32, u32)>,
    memory_bytes: u64,
    pids: u32,
    cpu_micros: u32,
    cpus: Option<&'a Set>,
    memory_nodes: Option<&'a Set>,
}
impl<'a> From<&'a Process> for Workload<'a> {
    fn from(process: &'a Process) -> Self {
        Self {
            name: format!("vm-{}", process.id),
            identity: process.identity,
            memory_bytes: process.memory_bytes,
            pids: process.pids,
            cpu_micros: process.cpu_micros,
            cpus: process.cpus.as_ref(),
            memory_nodes: process.memory_nodes.as_ref(),
        }
    }
}
impl Workload<'_> {
    pub(crate) fn driver(driver: &DriverArtifact) -> Result<Self> {
        let attachment = driver.attachment.as_ref().ok_or("missing driver attachment")?;
        Ok(Self {
            name: format!("driver-{}", driver.id),
            identity: Some(attachment.identity),
            memory_bytes: attachment.memory_bytes,
            pids: attachment.pids,
            cpu_micros: attachment.cpu_micros,
            cpus: None,
            memory_nodes: None,
        })
    }
}
impl Hierarchy {
    /// Stop the exclusive deployment tree in one kernel operation. A failed
    /// root operation is reported even if the leaf-level fallback succeeds.
    pub(crate) fn kill(&self) -> Result<()> {
        if let Err(error) = self.root.kill() {
            for child in &self.children {
                let _ = child.kill();
            }
            return Err(format!("could not force-stop the deployment cgroup: {error}"));
        }
        Ok(())
    }

    pub(crate) fn empty(&self) -> Result<bool> {
        self.root.empty()
    }

    /// Reclaim only the exact instance set bound to a locked durable approval.
    /// The caller must hold that journal's exclusive lock. Unknown child groups
    /// stop recovery before any signal; existing known children must all drain
    /// before their directories are removed and a fresh hierarchy is admitted.
    pub fn reclaim(path: &Path, deployment: &str, instances: &[&str]) -> Result<()> {
        let parent = delegated_parent(path)?;
        let name = format!("wros-{deployment}");
        let encoded = component(&name)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                encoded.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e.to_string())
            };
        }
        let directory = unsafe { File::from_raw_fd(fd) };
        owner(&directory)?;
        let expected = instances
            .iter()
            .map(|s| format!("vm-{s}"))
            .collect::<std::collections::BTreeSet<_>>();
        let mut children = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
            .map_err(|e| e.to_string())?
        {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| "invalid old cgroup name")?;
                if !expected.contains(&name) {
                    return Err("unapproved child cgroup prevents recovery".into());
                }
                let child = open_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
                owner(&child)?;
                // Guests have no cgroup creation rights. An unexpected subtree
                // therefore needs an administrator instead of recursive deletion.
                if std::fs::read_dir(format!("/proc/self/fd/{}", child.as_raw_fd()))
                    .map_err(|e| e.to_string())?
                    .any(|e| e.and_then(|e| e.file_type()).map_or(true, |t| t.is_dir()))
                {
                    return Err("unexpected nested cgroup prevents recovery".into());
                }
                children.push((component(&name)?, child));
            }
        }
        let root = Group {
            directory,
            parent,
            name: encoded,
        };
        root.drain(Duration::from_secs(2))?;
        for (name, _child) in children {
            if unsafe {
                libc::unlinkat(
                    root.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err(error());
            }
        }
        // Drop removes the empty known root. A failed removal is detected by the
        // subsequent exclusive create; it can never cause attachment to old work.
        drop(root);
        Ok(())
    }
    pub fn create(path: &Path, deployment: &str, processes: &[&Process]) -> Result<Self> {
        let workloads = processes.iter().map(|&p| Workload::from(p)).collect::<Vec<_>>();
        Self::create_workloads(path, deployment, &workloads)
    }

    pub(crate) fn create_workloads(path: &Path, deployment: &str, processes: &[Workload<'_>]) -> Result<Self> {
        let parent = delegated_parent(path)?;
        let controllers = read(&parent, "cgroup.subtree_control")?;
        for required in ["cpu", "memory", "pids"] {
            if !controllers.split_whitespace().any(|s| s == required) {
                return Err(format!(
                    "delegated subtree lacks enabled {required} controller"
                ));
            }
        }
        let placement = processes
            .iter()
            .any(|p| p.cpus.is_some() || p.memory_nodes.is_some());
        if placement {
            if !controllers.split_whitespace().any(|s| s == "cpuset") {
                return Err("explicit placement requires an enabled cpuset controller".into());
            }
            let cpus = Set::parse(read(&parent, "cpuset.cpus.effective")?.trim())?;
            let nodes = Set::parse(read(&parent, "cpuset.mems.effective")?.trim())?;
            for p in processes {
                if p.cpus.as_ref().is_some_and(|set| !cpus.contains(set))
                    || p.memory_nodes
                        .as_ref()
                        .is_some_and(|set| !nodes.contains(set))
                {
                    return Err(format!(
                        "Workload {:?} placement exceeds delegated effective CPU/NUMA sets",
                        p.name
                    ));
                }
            }
        }
        let parent_memory = read(&parent, "memory.max")?
            .trim()
            .parse::<u64>()
            .map_err(|_| "delegated subtree needs a finite memory.max")?;
        if read(&parent, "memory.swap.max")?.trim() != "0" {
            return Err("delegated subtree needs memory.swap.max=0".into());
        }
        let mut memory = 0u64;
        let mut pids = 0u64;
        for p in processes {
            if p.identity.is_none() {
                return Err("run needs an explicit UID and GID for every workload".into());
            }
            memory = memory
                .checked_add(p.memory_bytes)
                .ok_or("aggregate memory overflow")?;
            pids = pids
                .checked_add(u64::from(p.pids))
                .ok_or("aggregate task overflow")?;
        }
        if memory == 0 || memory > parent_memory {
            return Err("workload memory reservations exceed delegated budget".into());
        }
        let root = Group::create(&parent, &format!("wros-{deployment}"))?;
        // Require the whole-tree control before starting any VM.
        root.kill()?;
        write(&root.directory, "memory.max", &memory.to_string())?;
        write(&root.directory, "memory.swap.max", "0")?;
        write(&root.directory, "pids.max", &pids.to_string())?;
        write(
            &root.directory,
            "cgroup.subtree_control",
            if placement {
                "+cpu +memory +pids +cpuset"
            } else {
                "+cpu +memory +pids"
            },
        )?;
        let mut hierarchy = Self {
            children: Vec::with_capacity(processes.len()),
            root,
        };
        for p in processes {
            let child = Group::create(&hierarchy.root.directory, &p.name)?;
            write(&child.directory, "memory.max", &p.memory_bytes.to_string())?;
            write(&child.directory, "memory.swap.max", "0")?;
            write(&child.directory, "memory.oom.group", "1")?;
            write(&child.directory, "pids.max", &p.pids.to_string())?;
            write(
                &child.directory,
                "cpu.max",
                &format!("{} 100000", p.cpu_micros),
            )?;
            if let Some(nodes) = p.memory_nodes {
                write(&child.directory, "cpuset.mems", &nodes.to_string())?;
            }
            if let Some(cpus) = p.cpus {
                write(&child.directory, "cpuset.cpus", &cpus.to_string())?;
            }
            child.verify_sets(p.cpus, p.memory_nodes)?;
            // The attachment remains effective even when this local handle or
            // the supervisor dies. It ends only with the drained cgroup itself.
            let _device_policy = crate::devices::Policy::vm().attach_empty(&child.directory)?;
            // Verify support before the first child exists.
            child.kill()?;
            hierarchy.children.push(child);
        }
        Ok(hierarchy)
    }
}
