//! Local, bounded, closed XML deployment and recommendation formats.
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_XML: u64 = 256 * 1024;
/// Execution strategy for a reviewed application VM. Both engines enforce
/// the same guest permissions. This setting grants no compiler threads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    Aot,
    Interpreter,
}
impl Engine {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Aot => "--runtime-aot",
            Self::Interpreter => "--runtime-int",
        }
    }
}
#[derive(Debug)]
pub struct Process {
    pub id: String,
    pub engine: Engine,
    pub module: PathBuf,
    pub digest: String,
    pub policy: PathBuf,
    pub vm_policy: Option<PathBuf>,
    pub boot_start: bool,
    pub crash_restart: bool,
    pub recommendations: Option<PathBuf>,
    pub memory_bytes: u64,
    pub pids: u32,
    pub identity: Option<(u32, u32)>,
    pub cpu_micros: u32,
    pub restart_limit: u32,
    pub restart_delay_ms: u32,
    pub cpus: Option<crate::placement::Set>,
    pub memory_nodes: Option<crate::placement::Set>,
}
#[derive(Debug)]
pub struct DriverArtifact {
    pub id: String,
    pub file: PathBuf,
    pub digest: String,
    pub vendor_version: String,
    pub kind: String,
    pub hardware_id: String,
}
#[derive(Debug)]
pub struct Deployment {
    pub id: String,
    pub processes: Vec<Process>,
    pub drivers: Vec<DriverArtifact>,
    pub supervisor: Option<Supervisor>,
}
/// Explicit budget for the privileged manager and its admission verifier.
/// Workload budgets are separate; neither budget is an emergency-stop promise.
#[derive(Debug)]
pub struct Supervisor {
    pub memory_bytes: u64,
    pub pids: u32,
    pub cpu_micros: u32,
    pub cpus: Option<crate::placement::Set>,
    pub memory_nodes: Option<crate::placement::Set>,
}
pub fn read_xml(p: &Path) -> Result<String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(p)
        .map_err(|e| e.to_string())?;
    xml_contents(f)
}
pub fn xml_contents(f: File) -> Result<String> {
    if !f.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("expected regular XML file".into());
    }
    let mut data = String::new();
    f.take(MAX_XML + 1)
        .read_to_string(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_XML {
        return Err("XML exceeds byte budget".into());
    }
    Ok(data)
}
fn document(s: &str) -> Result<Document<'_>> {
    if s.len() as u64 > MAX_XML {
        return Err("XML exceeds byte budget".into());
    }
    let mut options = ParsingOptions::default();
    options.allow_dtd = false;
    options.nodes_limit = 4096;
    Document::parse_with_options(s, options).map_err(|e| e.to_string())
}
fn attributes(n: Node, name: &str, allowed: &[&str]) -> Result<()> {
    if n.tag_name().name() != name
        || n.tag_name().namespace().is_some()
        || n.namespaces().next().is_some()
        || n.attributes()
            .any(|a| a.namespace().is_some() || !allowed.contains(&a.name()))
        || n.children()
            .any(|x| x.is_pi() || (x.is_text() && !x.text().unwrap_or("").trim().is_empty()))
    {
        return Err(format!(
            "unexpected element, attribute or content in {name}"
        ));
    }
    Ok(())
}
fn attr<'a>(n: Node<'a, 'a>, key: &str) -> Result<&'a str> {
    n.attribute(key)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing {key}"))
}
fn flag(node: Node, name: &str) -> Result<bool> {
    match node.attribute(name) {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        _ => Err(format!("invalid boolean {name}")),
    }
}
pub fn known_interface(key: &str) -> bool {
    include_str!("../protocol/ros-interfaces.txt")
        .lines()
        .any(|name| name == key)
}
/// The durable key includes the authority namespace. ROS names keep their
/// existing spelling. Only clock imports and their independent read rights
/// can select a Preview 1 policy; no path, descriptor or socket names qualify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission<'a> {
    RosInterface(&'a str),
    ClockInterface(&'a str),
    ClockGrant(&'a str),
}
impl<'a> Permission<'a> {
    pub fn from_key(key: &'a str) -> Option<Self> {
        if let Some(grant) = key.strip_prefix("wasip1.clock.") {
            return match grant {
                "realtime-clock" | "monotonic-clock" | "process-clock" | "thread-clock"
                | "realtime-resolution" | "monotonic-resolution" | "process-resolution"
                | "thread-resolution" => Some(Self::ClockGrant(grant)),
                _ => None,
            };
        }
        if let Some(name) = key.strip_prefix("wasip1.") {
            return match name {
                "clock_res_get" | "clock_time_get" | "clock_res_get_wasm64"
                | "clock_time_get_wasm64" => Some(Self::ClockInterface(name)),
                _ => None,
            };
        }
        known_interface(key).then_some(Self::RosInterface(key))
    }
}
fn id(s: &str) -> bool {
    s.len() <= 128
        && !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn path(s: &str) -> Result<PathBuf> {
    let p = Path::new(s);
    if s.contains(':') || s.contains('\\') {
        return Err("expected a local path without a URI scheme".into());
    }
    if s.is_empty()
        || s.bytes().any(|x| x < 32 || x == 127)
        || !p.components().all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("expected bundle-relative path".into());
    }
    Ok(p.into())
}
pub fn deployment(s: &str) -> Result<Deployment> {
    let d = document(s)?;
    let root = d.root_element();
    attributes(root, "deployment", &["id"])?;
    let name = attr(root, "id")?;
    if !id(name) {
        return Err("invalid deployment ID".into());
    }
    let mut processes = Vec::new();
    let mut drivers = Vec::new();
    let mut supervisor = None;
    let mut hardware = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for node in root.children().filter(Node::is_element) {
        if node.tag_name().name() == "supervisor" {
            attributes(
                node,
                "supervisor",
                &["memory-bytes", "pids", "cpu-micros", "cpus", "memory-nodes"],
            )?;
            if supervisor.is_some() || node.children().any(|n| n.is_element()) {
                return Err("exactly one leaf supervisor configuration is permitted".into());
            }
            let memory_bytes = attr(node, "memory-bytes")?
                .parse::<u64>()
                .map_err(|_| "invalid supervisor memory budget")?;
            let pids = attr(node, "pids")?
                .parse::<u32>()
                .map_err(|_| "invalid supervisor task budget")?;
            let cpu_micros = attr(node, "cpu-micros")?
                .parse::<u32>()
                .map_err(|_| "invalid supervisor CPU budget")?;
            if memory_bytes < 16 * 1024 * 1024
                || !(8..=65536).contains(&pids)
                || !(1000..=100_000_000).contains(&cpu_micros)
            {
                return Err("invalid supervisor resource bounds".into());
            }
            supervisor = Some(Supervisor {
                memory_bytes,
                pids,
                cpu_micros,
                cpus: node
                    .attribute("cpus")
                    .map(crate::placement::Set::parse)
                    .transpose()?,
                memory_nodes: node
                    .attribute("memory-nodes")
                    .map(crate::placement::Set::parse)
                    .transpose()?,
            });
            continue;
        }
        if node.tag_name().name() == "driver" {
            attributes(
                node,
                "driver",
                &[
                    "id",
                    "file",
                    "sha256",
                    "vendor-version",
                    "kind",
                    "hardware-id",
                ],
            )?;
            let name = attr(node, "id")?;
            let key = attr(node, "hardware-id")?;
            let digest = attr(node, "sha256")?;
            let kind = attr(node, "kind")?;
            let version = attr(node, "vendor-version")?;
            if drivers.len() >= 128
                || !id(name)
                || !id(key)
                || !ids.insert(name)
                || !hardware.insert(key)
                || !matches!(kind, "shared-library" | "executable")
                || digest.len() != 64
                || !digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                || version.len() > 128
                || !version.bytes().all(|b| b.is_ascii_graphic())
                || node.children().any(|n| n.is_element())
            {
                return Err("invalid driver or conflicting hardware owner".into());
            }
            drivers.push(DriverArtifact {
                id: name.into(),
                file: path(attr(node, "file")?)?,
                digest: digest.into(),
                hardware_id: key.into(),
                kind: kind.into(),
                vendor_version: version.into(),
            });
            continue;
        }
        attributes(
            node,
            "vm",
            &[
                "id",
                "module",
                "sha256",
                "policy",
                "vm-policy",
                "engine",
                "recommendations",
                "memory-bytes",
                "pids",
                "start-on-boot",
                "restart-on-crash",
                "uid",
                "gid",
                "cpu-micros",
                "restart-limit",
                "restart-delay-ms",
                "cpus",
                "memory-nodes",
            ],
        )?;
        let name = attr(node, "id")?;
        let digest = attr(node, "sha256")?;
        if node.children().any(|n| n.is_element())
            || processes.len() >= 128
            || !id(name)
            || !ids.insert(name)
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid or duplicate VM identity or digest".into());
        }
        let memory_bytes = attr(node, "memory-bytes")?
            .parse::<u64>()
            .map_err(|_| "invalid memory budget")?;
        let pids = attr(node, "pids")?
            .parse::<u32>()
            .map_err(|_| "invalid task budget")?;
        if memory_bytes == 0 || pids == 0 {
            return Err("process budgets must be positive".into());
        }
        let number = |key: &str, default: u32| -> Result<u32> {
            node.attribute(key)
                .map(|v| v.parse::<u32>().map_err(|_| format!("invalid {key}")))
                .unwrap_or(Ok(default))
        };
        let identity = match (node.attribute("uid"), node.attribute("gid")) {
            (None, None) => None,
            (Some(_), Some(_)) => {
                let uid = number("uid", 0)?;
                let gid = number("gid", 0)?;
                if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX {
                    return Err("guest uid and gid must be non-root identities".into());
                }
                if processes
                    .iter()
                    .any(|p: &Process| p.identity.is_some_and(|(u, g)| u == uid || g == gid))
                {
                    return Err("each VM needs a distinct uid and gid".into());
                }
                Some((uid, gid))
            }
            _ => return Err("uid and gid must be specified together".into()),
        };
        let cpu_micros = number("cpu-micros", 100_000)?;
        let restart_limit = number("restart-limit", 3)?;
        let restart_delay_ms = number("restart-delay-ms", 1000)?;
        if !(1000..=100_000_000).contains(&cpu_micros)
            || restart_limit > 32
            || !(100..=60_000).contains(&restart_delay_ms)
        {
            return Err("invalid CPU or restart bounds".into());
        }
        processes.push(Process {
            id: name.into(),
            engine: match node.attribute("engine").unwrap_or("aot") {
                "aot" => Engine::Aot,
                "interpreter" => Engine::Interpreter,
                _ => return Err("VM engine must be aot or interpreter".into()),
            },
            module: path(attr(node, "module")?)?,
            digest: digest.into(),
            policy: path(attr(node, "policy")?)?,
            boot_start: flag(node, "start-on-boot")?,
            crash_restart: flag(node, "restart-on-crash")?,
            recommendations: node.attribute("recommendations").map(path).transpose()?,
            memory_bytes,
            pids,
            vm_policy: node.attribute("vm-policy").map(path).transpose()?,
            identity,
            cpu_micros,
            restart_limit,
            restart_delay_ms,
            cpus: node
                .attribute("cpus")
                .map(crate::placement::Set::parse)
                .transpose()?,
            memory_nodes: node
                .attribute("memory-nodes")
                .map(crate::placement::Set::parse)
                .transpose()?,
        })
    }
    if processes.is_empty() {
        return Err("empty deployment".into());
    }
    Ok(Deployment {
        id: name.into(),
        processes,
        drivers,
        supervisor,
    })
}
pub fn recommendations(s: &str) -> Result<BTreeMap<String, bool>> {
    let d = document(s)?;
    let root = d.root_element();
    attributes(root, "recommendations", &[])?;
    let mut grants = BTreeMap::new();
    for n in root.children().filter(Node::is_element) {
        let (key, decision) = match n.tag_name().name() {
            "interface" => {
                attributes(n, "interface", &["name", "expose"])?;
                let key = attr(n, "name")?;
                if !matches!(Permission::from_key(key), Some(Permission::RosInterface(_) | Permission::ClockInterface(_))) {
                    return Err("invalid interface".into());
                }
                (key.to_owned(), attr(n, "expose")?)
            }
            "wasip1-clock" => {
                attributes(n, "wasip1-clock", &["name", "access"])?;
                let key = format!("wasip1.clock.{}", attr(n, "name")?);
                if !matches!(Permission::from_key(&key), Some(Permission::ClockGrant(_))) {
                    return Err("invalid WASIp1 clock read permission".into());
                }
                (key, attr(n, "access")?)
            }
            _ => return Err("unexpected recommendation element".into()),
        };
        if grants.len() >= 256 || n.children().any(|x| x.is_element()) {
            return Err("invalid permission count or nested recommendation".into());
        }
        let enabled = match decision {
            "allow" => true,
            "deny" => false,
            _ => return Err("permission must be allow or deny".into()),
        };
        if grants.insert(key, enabled).is_some() {
            return Err("duplicate interface".into());
        }
    }
    Ok(grants)
}
/// Resolve each component relative to a pinned directory descriptor. Symlinks
/// never acquire access outside the submitted bundle, even during replacement.
pub fn local_file(root: &File, relative: &Path) -> Result<File> {
    let mut directory = root.try_clone().map_err(|e| e.to_string())?;
    let mut parts = relative.components().peekable();
    while let Some(component) = parts.next() {
        let Component::Normal(part) = component else {
            return Err("invalid bundle path".into());
        };
        let part = CString::new(part.as_bytes()).map_err(|e| e.to_string())?;
        let last = parts.peek().is_none();
        let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_RDONLY;
        if !last {
            flags |= libc::O_DIRECTORY;
        }
        // The directory remains open during the syscall and the result has one owner.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), part.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        let next = unsafe { File::from_raw_fd(fd) };
        if last {
            if !next.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("bundle artifact must be a regular file".into());
            }
            return Ok(next);
        }
        directory = next;
    }
    Err("empty bundle path".into())
}

pub fn sha256(mut input: File) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    io::copy(&mut input, &mut hash).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", hash.finalize()))
}
