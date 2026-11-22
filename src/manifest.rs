//! Local, bounded, closed XML deployment and recommendation formats.
use roxmltree::{Document, Node, ParsingOptions};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
};
use std::path::{Component, Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;
pub const MAX_XML: u64 = 256 * 1024;
pub const MAX_PERMISSIONS: usize = 256;
pub const NATIVE_PRELOAD_REFUSED: &str =
    "in-process native preload is unsupported (10/10 high risk); isolated ELF drivers use individual admission";

/// Distinguish a request to load native code from querying the runtime's
/// read-only `report/preloaddl` selector.
pub fn native_preload_request(key: &str) -> bool {
    matches!(key, "--wasm-register-dl" | "-Wdl" | "preloaddl")
        || key.starts_with("preloaddl/") || key.starts_with("preloaddl.")
}
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
#[derive(Clone, Debug)]
pub struct Process {
    pub id: String,
    pub engine: Engine,
    pub aot_policy: Option<&'static str>,
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
#[derive(Clone, Debug)]
pub struct DriverArtifact {
    pub id: String,
    pub file: PathBuf,
    pub digest: String,
    pub vendor_version: String,
    pub kind: String,
    pub hardware_id: String,
    pub elf_signer: Option<PathBuf>,
    pub attachment: Option<DriverAttachment>,
}
#[derive(Clone, Debug)]
pub struct DriverAttachment {
    pub vm: String,
    pub alias: String,
    pub socket_contract: [u8; 32],
    pub sandbox: PathBuf,
    pub identity: (u32, u32),
    pub memory_bytes: u64,
    pub pids: u32,
    pub cpu_micros: u32,
    pub request_millis: u32,
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
    xml_contents(open_regular(p, MAX_XML)?)
}

/// Acquire a reference without opening file contents, then admit a regular file.
pub(crate) fn open_regular(path: &Path, maximum: u64) -> Result<File> {
    let pin = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    reopen_regular(pin, maximum)
}

/// Check an O_PATH handle before reopening the same inode. Special files can
/// require effects merely to open them, so even a nonblocking read must wait
/// for the regular-file check.
fn reopen_regular(pin: File, maximum: u64) -> Result<File> {
    let meta = pin.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > maximum {
        return Err("expected a regular file within the size limit".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(format!("/proc/self/fd/{}", pin.as_raw_fd()))
        .map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
        return Err("unable to reopen the pinned regular file".into());
    }
    Ok(file)
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
    LegacyRosAbi { host: &'static str, interface: &'static str },
    ClockInterface(&'a str),
    ClockGrant(&'a str),
    LocalOperation { kind: &'a str, alias: &'a str, operation: &'a str },
    SelfReport(&'a str),
    DriverRead(&'a str),
    Metadata { kind: &'a str, alias: &'a str, target: &'a str, operation: &'a str },
}
impl<'a> Permission<'a> {
    /// Host scheduling resources are private to the named VM. Validate all three
    /// fields before forming a durable review key or emitting a VM argument.
    fn local(kind: &'a str, alias: &'a str, operation: &'a str) -> Option<Self> {
        if !id(alias) || alias.starts_with('-') || 8 + kind.len() + alias.len() + operation.len() > 128 {
            return None;
        }
        let specific = match kind {
            "guard" => matches!(operation, "guard.create" | "guard.trigger" | "guard.take"),
            "clock.steady" | "clock.system" => matches!(operation, "clock.create" | "clock.read"),
            "clock.ros" => matches!(operation, "clock.create" | "clock.read" | "clock.update"),
            "timer" => matches!(operation, "timer.create" | "timer.reset" | "timer.cancel" | "timer.take"),
            "wait" => matches!(operation, "wait.create" | "wait.add" | "wait.remove" | "wait.acknowledge" | "wait.poll"),
            _ => return None,
        };
        (specific || matches!(operation, "resource.observe" | "resource.close" | "capability.revoke"))
            .then_some(Self::LocalOperation { kind, alias, operation })
    }

    /// Observation grants use a fixed binding. A deployed VM may read only the
    /// named target and operation. No selector is interpreted as a host path.
    fn metadata(kind: &'a str, alias: &'a str, target: &'a str, operation: &'a str) -> Option<Self> {
        if !id(alias) || alias.starts_with('-') || target.is_empty() || matches!(target, "." | "..") || target.starts_with('-') ||
            !target.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) ||
            12 + kind.len() + alias.len() + target.len() + operation.len() > 128 {
            return None;
        }
        let valid = match kind {
            "vm" => target == "runtime" && operation == "vm.describe",
            "module" => matches!(operation, "module.describe" | "module.imports" | "module.exports" |
                "module.importers" | "module.group" | "module.permission.report"),
            _ => false,
        };
        valid.then_some(Self::Metadata { kind, alias, target, operation })
    }

    pub fn from_key(key: &'a str) -> Option<Self> {
        match key {
            "uwvm_ros1_v1.abi_version" => return Some(Self::LegacyRosAbi {
                host: "ros1", interface: "uwvm_ros1_v1.abi_version",
            }),
            "uwvm_ros2_v1.abi_version" => return Some(Self::LegacyRosAbi {
                host: "ros2", interface: "uwvm_ros2_v1.abi_version",
            }),
            _ => {}
        }
        if let Some(alias) = key.strip_prefix("driver/").and_then(|rest| rest.strip_suffix("/buffer.read")) {
            return (id(alias) && !alias.starts_with('-') && key.len() <= 128)
                .then_some(Self::DriverRead(alias));
        }
        if let Some(selector) = key.strip_prefix("report/") {
            let (family, function) = selector.split_once('.').map_or((selector, None), |(f, n)| (f, Some(n)));
            if !matches!(family, "wasip1" | "ros1v1" | "ros2v1" | "rosv2" | "preloaddl" | "preloadwasm") ||
                function.is_some_and(|n| n.is_empty() || matches!(n, "." | "..") || n.len() > 255 ||
                    !n.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))) {
                return None;
            }
            return Some(Self::SelfReport(selector));
        }
        if let Some(rest) = key.strip_prefix("metadata/") {
            let (kind, rest) = rest.split_once('/')?;
            let (alias, rest) = rest.split_once('/')?;
            let (target, operation) = rest.split_once('/')?;
            return Self::metadata(kind, alias, target, operation);
        }
        if let Some(local) = key.strip_prefix("local/") {
            let (kind, rest) = local.split_once('/')?;
            let (alias, operation) = rest.split_once('/')?;
            return Self::local(kind, alias, operation);
        }
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
/// The VM registers each alias once. Independent action decisions share that
/// registration. Omit aliases without a grant so capability.open stays denied.
pub struct ReviewedGrant<'a> {
    pub kind: &'a str,
    pub target: &'a str,
    pub binding: &'static str,
    pub operations: Vec<&'a str>,
}
pub fn reviewed_grants(rights: &BTreeMap<String, bool>) -> Result<BTreeMap<&str, ReviewedGrant<'_>>> {
    if rights.len() > MAX_PERMISSIONS {
        return Err("permission count exceeds budget".into());
    }
    let mut aliases = BTreeMap::new();
    for (key, allow) in rights {
        let (alias, kind, target, binding, operation) = match Permission::from_key(key).ok_or("unknown reviewed permission")? {
            Permission::LocalOperation { kind, alias, operation } => (alias, kind, alias, "local", operation),
            Permission::Metadata { kind, alias, target, operation } => (alias, kind, target, "metadata", operation),
            _ => continue,
        };
        let prior = aliases.entry(alias).or_insert_with(|| ReviewedGrant { kind, target, binding, operations: Vec::new() });
        if (prior.kind, prior.target, prior.binding) != (kind, target, binding) {
            return Err(format!("conflicting resource bindings for {alias}"));
        }
        if *allow { prior.operations.push(operation); }
    }
    aliases.retain(|_, grant| !grant.operations.is_empty());
    Ok(aliases)
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

fn driver_attachment(node: Node) -> Result<DriverAttachment> {
    attributes(node, "attachment", &[
        "vm", "alias", "contract-sha256", "sandbox", "uid", "gid", "memory-bytes", "pids", "cpu-micros", "request-millis",
    ])?;
    let vm = attr(node, "vm")?;
    let alias = attr(node, "alias")?;
    if node.children().any(|n| n.is_element())
        || !id(vm) || vm.starts_with('-')
        || !matches!(Permission::from_key(&format!("driver/{alias}/buffer.read")), Some(Permission::DriverRead(_)))
    {
        return Err("invalid driver attachment endpoints".into());
    }
    let number = |name| -> Result<u32> {
        attr(node, name)?.parse().map_err(|_| format!("invalid driver {name}"))
    };
    let identity = (number("uid")?, number("gid")?);
    let pids = number("pids")?;
    let cpu_micros = number("cpu-micros")?;
    let request_millis = if node.attribute("request-millis").is_some() {
        number("request-millis")?
    } else {
        2000
    };
    let memory_bytes = attr(node, "memory-bytes")?.parse()
        .map_err(|_| "invalid driver memory budget")?;
    if [identity.0, identity.1].iter().any(|n| *n == 0 || *n == u32::MAX)
        || !(1..=65536).contains(&pids)
        || !(1000..=100_000_000).contains(&cpu_micros)
        || !(1..=180_000).contains(&request_millis)
        || memory_bytes == 0
    {
        return Err("driver requires a non-root identity and bounded resources".into());
    }
    let digest = attr(node, "contract-sha256")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid driver contract digest".into());
    }
    let mut socket_contract = [0; 32];
    for (index, value) in socket_contract.iter_mut().enumerate() {
        *value = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid driver contract digest")?;
    }
    if socket_contract == [0; 32] {
        return Err("driver contract digest cannot be zero".into());
    }
    Ok(DriverAttachment {
        vm: vm.into(), alias: alias.into(), socket_contract, sandbox: path(attr(node, "sandbox")?)?,
        identity, memory_bytes, pids, cpu_micros, request_millis,
    })
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
                    "elf-signer",
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
            {
                return Err("invalid driver or conflicting hardware owner".into());
            }
            let mut children = node.children().filter(Node::is_element);
            let attachment = children.next().map(driver_attachment).transpose()?;
            if children.next().is_some() || (attachment.is_some() && kind != "executable") {
                return Err("an executable driver may define one attachment".into());
            }
            drivers.push(DriverArtifact {
                id: name.into(),
                file: path(attr(node, "file")?)?,
                digest: digest.into(),
                hardware_id: key.into(),
                kind: kind.into(),
                vendor_version: version.into(),
                elf_signer: node.attribute("elf-signer").map(path).transpose()?,
                attachment,
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
                "aot-policy",
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
        let engine = match node.attribute("engine").unwrap_or("aot") {
            "aot" => Engine::Aot,
            "interpreter" => Engine::Interpreter,
            _ => return Err("VM engine must be aot or interpreter".into()),
        };
        let aot_policy = match (engine, node.attribute("aot-policy")) {
            (_, None) => None,
            (Engine::Interpreter, Some(_)) => return Err("aot-policy requires the AOT engine".into()),
            (Engine::Aot, Some("default")) => Some("default"),
            (Engine::Aot, Some("fast-compile")) => Some("fast-compile"),
            (Engine::Aot, Some("balanced")) => Some("balanced"),
            (Engine::Aot, Some("max")) => Some("max"),
            _ => return Err("unknown deployment AOT policy".into()),
        };
        processes.push(Process {
            id: name.into(),
            engine,
            aot_policy,
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
    let mut attached_vms = BTreeSet::new();
    let mut uids = processes.iter().filter_map(|p| p.identity.map(|(uid, _)| uid)).collect::<BTreeSet<_>>();
    let mut gids = processes.iter().filter_map(|p| p.identity.map(|(_, gid)| gid)).collect::<BTreeSet<_>>();
    for attachment in drivers.iter().filter_map(|driver| driver.attachment.as_ref()) {
        if !processes.iter().any(|p| p.id == attachment.vm)
            || !attached_vms.insert(&attachment.vm)
            || !uids.insert(attachment.identity.0) || !gids.insert(attachment.identity.1)
        {
            return Err("driver attachment requires an existing dedicated VM and distinct host identities".into());
        }
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
                if native_preload_request(key) {
                    return Err(NATIVE_PRELOAD_REFUSED.into());
                }
                if !matches!(Permission::from_key(key), Some(Permission::RosInterface(_) | Permission::LegacyRosAbi { .. } | Permission::ClockInterface(_))) {
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
            "self-report" => {
                attributes(n, "self-report", &["selector", "access"])?;
                let key = format!("report/{}", attr(n, "selector")?);
                Permission::from_key(&key).ok_or("invalid permission-report selector")?;
                (key, attr(n, "access")?)
            }
            "driver-resource" => {
                attributes(n, "driver-resource", &["alias", "operation", "access"])?;
                let key = format!("driver/{}/{}", attr(n, "alias")?, attr(n, "operation")?);
                Permission::from_key(&key).ok_or("invalid driver resource or operation")?;
                (key, attr(n, "access")?)
            }
            "metadata" => {
                attributes(n, "metadata", &["type", "alias", "target", "operation", "access"])?;
                let (kind, alias, target, op) = (attr(n,"type")?, attr(n,"alias")?, attr(n,"target")?, attr(n,"operation")?);
                Permission::metadata(kind, alias, target, op).ok_or("invalid metadata target or operation")?;
                (format!("metadata/{kind}/{alias}/{target}/{op}"), attr(n,"access")?)
            }
            "local-resource" => {
                attributes(n, "local-resource", &["type", "alias", "operation", "access"])?;
                let (kind, alias, op) = (attr(n, "type")?, attr(n, "alias")?, attr(n, "operation")?);
                Permission::local(kind, alias, op).ok_or("invalid local resource or operation")?;
                (format!("local/{kind}/{alias}/{op}"), attr(n, "access")?)
            }
            _ => return Err("unexpected recommendation element".into()),
        };
        if grants.len() >= MAX_PERMISSIONS || n.children().any(|x| x.is_element()) {
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
    reviewed_grants(&grants)?;
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
        let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_PATH;
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
            return reopen_regular(next, u64::MAX);
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
