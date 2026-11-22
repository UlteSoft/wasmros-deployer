//! Deployment-specific assessments and the operator's final confirmation.
use wros_deployer::manifest::{Deployment, Permission, Result, HIDE_SELF_REPORT, SELF_REPORT};
use wros_deployer::guest_imports::ImportAssessment;
use wros_deployer::verdict::Signature;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead, IsTerminal, Write};
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Risk {
    Scored(u8, &'static str),
    Unassessed(&'static str),
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scored(score, reason) => {
                let class = match score {
                    0 => "informational",
                    1..=3 => "low",
                    4..=6 => "moderate",
                    _ => "high",
                };
                write!(f, "{score}/10 ({class}) — {reason}")
            }
            Self::Unassessed(reason) => write!(f, "UNASSESSED — {reason}"),
        }
    }
}

/// Operator output filter. No display mode modifies permission decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskReport {
    None,
    AtLeast(u8),
}

impl Default for RiskReport {
    fn default() -> Self { Self::AtLeast(7) }
}

impl RiskReport {
    pub fn parse(value: &str) -> Result<Self> {
        if value == "none" { return Ok(Self::None); }
        let grade = value.strip_prefix(">=").unwrap_or(value);
        match grade.as_bytes() {
            [n @ b'0'..=b'9'] => Ok(Self::AtLeast(n - b'0')),
            b"10" => Ok(Self::AtLeast(10)),
            _ => Err("invalid --risk-report value; use none or a threshold from 0 through 10, optionally prefixed with >=".into()),
        }
    }

    fn show(self, label: &str, items: impl IntoIterator<Item = (String, Risk)>) {
        let Self::AtLeast(minimum) = self else { return };
        let mut unknown = Vec::new();
        let mut shown = false;
        println!("Risk report {label} (threshold >={minimum}/10)");
        for (subject, risk) in items {
            match risk {
                Risk::Scored(score, _) if score >= minimum => {
                    println!("  {subject}: {risk}");
                    shown = true;
                }
                Risk::Unassessed(reason) => unknown.push((subject, reason)),
                _ => {}
            }
        }
        if !shown {
            println!("  no scored items at this threshold");
        }
        if !unknown.is_empty() {
            println!("  UNASSESSED");
            for (subject, reason) in unknown {
                println!("    {subject}: {reason}");
            }
        }
    }
}

fn operation_risk(name: &str) -> Risk {
    let (score, reason) = match name {
        "abi" => (0, "reports the ROSv2 ABI version"),
        "clock.read" => (0, "reads a clock through a separately authorized handle"),
        "permission.report" | "type.describe" => (1, "exposes permission or type metadata"),
        "clock.create" | "timer.create" | "timer.reset" | "timer.cancel" | "timer.take"
        | "guard.create" | "guard.take" | "guard.trigger"
        | "wait.create" | "wait.add" | "wait.remove" | "wait.poll" | "wait.acknowledge" =>
            (3, "manages or consumes process-local scheduling resources"),
        "clock.update" => (5, "changes a local ROS clock and can affect time-dependent behavior"),
        "resource.observe" | "resource.close" | "capability.close" | "capability.revoke" =>
            (3, "observes or closes a separately authorized local resource"),
        "capability.open" => (3, "opens only an alias independently authorized for this VM"),
        "driver.connect" | "driver.disconnect" | "driver.result" | "driver.submit" =>
            (6, "controls IPC with an isolated native provider; the supported driver grant is read-only"),
        "control.open" | "control.stop" | "control.submit" | "device.open" | "device.stop"
        | "device.submit" => (9, "can address a controller or device with operational consequences"),
        "action.cancel" | "action.cancel.set" | "action.respond" | "action.submit"
        | "lifecycle.respond" | "lifecycle.submit" | "service.respond" | "service.submit"
        | "topic.publish" | "transform.clear" | "transform.publish" | "transform.submit" =>
            (8, "can send a command or change state observed by other components"),
        "bridge.create" | "bridge.start" | "bridge.stop" =>
            (9, "can change communication across domains"),
        "artifact.append" | "artifact.begin" | "artifact.commit" | "artifact.publish" | "artifact.remove"
        | "recording.append" | "recording.checkpoint" | "recording.open" =>
            (7, "can write, publish, or remove data through a separate capability"),
        "parameter.declare" | "parameter.set" | "parameter.set.atomic" | "parameter.undeclare"
        | "module.call.submit" | "module.call.respond" | "context.shutdown" =>
            (7, "can change operational state or call another module"),
        "module.describe" | "module.exports" | "module.group" | "module.importers"
        | "module.imports" | "module.permission.report" | "vm.describe" =>
            (4, "can disclose metadata of a separately selected module or VM target"),
        "diagnostic.read" | "graph.snapshot" | "graph.watch" | "sensor.take" | "device.describe"
        | "driver.describe" | "control.sample" | "control.result" | "device.result" =>
            (4, "can disclose topology, diagnostics, or device data"),
        "action.describe" | "artifact.describe" | "artifact.receipt" | "artifact.status"
        | "bridge.describe" | "buffer.describe" | "context.describe" | "lifecycle.state"
        | "lifecycle.transitions" | "model.describe" | "node.describe"
        | "parameter.describe" | "parameter.exists" | "parameter.get" | "parameter.list"
        | "parameter.search" | "qos.describe" | "request.describe" | "sensor.describe"
        | "service.available" | "service.describe" | "topic.describe" | "transform.available"
        | "transform.lookup" | "transform.velocity" =>
            (4, "reads information through a separately authorized handle"),
        "artifact.open" | "artifact.read" | "buffer.read" | "media.take" | "replay.read" =>
            (5, "reads application data and can disclose its contents"),
        "buffer.create" | "buffer.seal" | "buffer.write" =>
            (4, "manages an independently authorized buffer"),
        "model.open" | "model.submit" | "media.open" | "media.submit" =>
            (6, "can submit data for processing through a separately authorized resource"),
        "log.emit" => (3, "writes diagnostic output"),
        _ => return Risk::Unassessed("registered interface with no reviewed risk classification; an independent resource grant may still be required"),
    };
    Risk::Scored(score, reason)
}

fn permission_risk(name: &str) -> Risk {
    match Permission::from_key(name) {
        Some(Permission::ClockInterface(_) | Permission::ClockGrant(_)) =>
            Risk::Scored(0, "read-only WASIp1 clock or resolution; interface and source grant are independent"),
        Some(Permission::LegacyRosAbi { .. }) =>
            Risk::Scored(0, "legacy ABI version only; requires an explicit legacy VM build and provides no ROS data or gateway rights"),
        Some(Permission::HideSelfReport) =>
            Risk::Scored(0, "hides the guest's read-only self report"),
        Some(Permission::RosInterface(operation) | Permission::LocalOperation { operation, .. }) =>
            operation_risk(operation),
        Some(Permission::Metadata { .. }) =>
            Risk::Scored(4, "reads metadata from a separately selected module or VM target"),
        Some(Permission::SelfReport("preloaddl")) =>
            Risk::Scored(1, "read-only native preload build status; grants no ability to load native code"),
        Some(Permission::SelfReport(_)) =>
            Risk::Scored(1, "leaves the VM's ordinary self-report visibility in place"),
        Some(Permission::DriverRead(_)) =>
            Risk::Scored(5, "reads data supplied by the named isolated native provider"),
        None => Risk::Unassessed("unknown permission key"),
    }
}

fn read_answer(input: &mut impl BufRead) -> Result<Option<String>> {
    // Control input is bounded even if a terminal sends an oversized line.
    let mut line = Vec::new();
    loop {
        let available = input.fill_buf().map_err(|e| e.to_string())?;
        if available.is_empty() { return Ok(None); }
        let end = available.iter().position(|b| *b == b'\n');
        let bytes = end.map_or(available.len(), |i| i + 1);
        if line.len() + bytes > 1024 {
            return Err("operator review cancelled because an answer exceeded 1024 bytes".into());
        }
        line.extend_from_slice(&available[..bytes]);
        input.consume(bytes);
        if end.is_some() {
            return String::from_utf8(line).map(Some).map_err(|_| "operator review requires UTF-8 input".into());
        }
    }
}

pub fn require_terminal() -> Result<()> {
    let error = "interactive review requires stdin, stdout and stderr on the same terminal; recommendations cannot authorize deployment";
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !io::stderr().is_terminal() {
        return Err(error.into());
    }
    let devices = [0, 1, 2].map(|fd| {
        std::fs::metadata(format!("/proc/self/fd/{fd}")).map(|meta| (meta.dev(), meta.ino(), meta.rdev()))
    });
    match devices {
        [Ok(input), Ok(output), Ok(prompts)] if input == output && output == prompts => Ok(()),
        _ => Err(error.into()),
    }
}

pub fn show_rights(phase: &str, vm: &str, rights: &BTreeMap<String, bool>, report: RiskReport) {
    println!("Review {phase} for VM {vm:?}");
    if rights.is_empty() {
        println!("  no explicit interface or resource decisions");
    }
    if !rights.contains_key(SELF_REPORT) && !rights.contains_key(HIDE_SELF_REPORT) {
        println!("  default read-only self observation via {SELF_REPORT:?}");
    }
    for (name, enabled) in rights {
        let (name, access) = decision(name, *enabled);
        println!("  {access} {name:?}");
    }
    report.show(&format!("VM {vm:?} {phase}"), rights.iter().map(|(key, enabled)| {
        let (name, access) = decision(key, *enabled);
        (format!("{access} {name:?} (risk if allowed)"), permission_risk(key))
    }));
    let wasip1 = rights.iter().filter(|(_, enabled)| **enabled).filter_map(|(key, _)| Permission::from_key(key));
    let (mut time, mut res, mut time_grant, mut res_grant) = (false, false, false, false);
    for key in wasip1 {
        match key {
            Permission::ClockInterface(name) if name.starts_with("clock_time_get") => time = true,
            Permission::ClockInterface(_) => res = true,
            Permission::ClockGrant(name) if name.ends_with("-clock") => time_grant = true,
            Permission::ClockGrant(_) => res_grant = true,
            _ => {}
        }
    }
    if time != time_grant || res != res_grant {
        println!("  WARNING incomplete WASIp1 clock access: each time or resolution operation needs both its interface and a matching source grant");
    }
}

fn decision(name: &str, enabled: bool) -> (&str, &str) {
    if name == HIDE_SELF_REPORT {
        (SELF_REPORT, "hidden")
    } else {
        (name, if enabled { "allow" } else { "deny" })
    }
}

fn edit(rights: &mut BTreeMap<String, bool>, name: &str, action: &str) -> Result<()> {
    let replacing_self = name == SELF_REPORT && (rights.contains_key(SELF_REPORT) || rights.contains_key(HIDE_SELF_REPORT));
    if action != "remove" && rights.len() >= wros_deployer::manifest::MAX_PERMISSIONS
        && !rights.contains_key(name) && !replacing_self {
        return Err("permission count exceeds budget; remove a decision before adding another".into());
    }
    if name == SELF_REPORT {
        rights.remove(HIDE_SELF_REPORT);
        rights.remove(SELF_REPORT);
    }
    match action {
        "allow" | "deny" => { rights.insert(name.into(), action == "allow"); }
        "hide" => { rights.insert(HIDE_SELF_REPORT.into(), true); }
        "remove" => { rights.remove(name); }
        _ => unreachable!("validated edit"),
    }
    Ok(())
}

pub fn approve(vm: &str, mut rights: BTreeMap<String, bool>, report: RiskReport) -> Result<BTreeMap<String, bool>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    for (key, enabled) in rights.clone() {
        let (name, recommendation) = decision(&key, enabled);
        let choices = if name == SELF_REPORT { "allow, deny or hide" } else { "allow or deny" };
        loop {
            eprint!(
                "VM {vm:?} {name:?} [recommended {recommendation}] review detail {}. {choices}? ",
                permission_risk(&key)
            );
            io::stderr().flush().map_err(|e| e.to_string())?;
            let answer = read_answer(&mut input)?.ok_or("review cancelled")?;
            match answer.trim() {
                action if matches!(action, "allow" | "deny") || (action == "hide" && name == SELF_REPORT) => {
                    edit(&mut rights, name, action)?;
                    break;
                }
                "cancel" => return Err("operator cancelled review".into()),
                _ => {}
            }
        }
    }
    loop {
        eprint!("VM {vm:?} edits [allow NAME | deny NAME | hide permission.report | remove NAME | show | confirm | cancel]: ");
        io::stderr().flush().map_err(|e| e.to_string())?;
        let line = read_answer(&mut input)?.ok_or("review cancelled")?;
        match line.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["cancel"] => return Err("operator cancelled review".into()),
            ["show"] => show_rights("pending", vm, &rights, report),
            ["confirm"] => match wros_deployer::manifest::reviewed_grants(&rights) {
                Ok(_) => return Ok(rights),
                Err(error) => eprintln!("{error}"),
            },
            [_, name] if wros_deployer::manifest::native_preload_request(name) =>
                eprintln!("{}", wros_deployer::manifest::NATIVE_PRELOAD_REFUSED),
            [action, name] if *name != HIDE_SELF_REPORT && Permission::from_key(name).is_some()
                && (matches!(*action, "allow" | "deny" | "remove") || (*action == "hide" && *name == SELF_REPORT)) => {
                if let Err(error) = edit(&mut rights, name, action) {
                    eprintln!("{error}");
                } else if matches!(*action, "allow" | "deny") {
                    println!("  input {name:?}; review detail {}", permission_risk(name));
                }
            }
            _ => eprintln!("enter a registered interface, a clock read permission or a local/, metadata/, report/ or driver/ decision, or confirm"),
        }
    }
}

pub fn show_deployment(plan: &Deployment, report: RiskReport) {
    println!("Deployment assessment: VM filesystem mounts, host folder access and guest sockets are unsupported by this manifest schema.");
    println!("Deployment assessment: legacy ROS is limited to the two independently reviewed ABI-version queries; production VMs omit legacy modules by default.");
    println!("Deployment assessment: in-process native preload is unavailable through this deployer; report/preloaddl controls read-only build-status visibility.");
    let mut items = vec![(
        "cross-VM DDS topic conflicts and independent motion interlocks".into(),
        Risk::Unassessed("this deployment format does not configure their endpoints"),
    )];
    for (i, a) in plan.processes.iter().enumerate() {
        items.push((format!("VM {:?} engine {:?}, AOT tuning {:?}", a.id, a.engine, a.aot_policy),
            Risk::Scored(2, "engine and compiler tuning can affect startup time and compute budgets")));
        items.push((format!("VM {:?} placement and resource budgets", a.id),
            Risk::Scored(4, "CPU, memory and task caps can delay or stop the workload; platform timing needs verification")));
        items.push((format!("VM {:?} automatic cold start at boot {}", a.id, a.boot_start),
            Risk::Scored(if a.boot_start {6} else {0}, "cold start grants no retained actuator authority")));
        items.push((format!("VM {:?} authorized crash restart {}", a.id, a.crash_restart),
            Risk::Scored(if a.crash_restart {5} else {0}, "configured cold restart can repeat initialization after a fault")));
        for b in &plan.processes[..i] {
            if let (Some(a_set), Some(b_set)) = (&a.cpus, &b.cpus) {
                if a_set.overlaps(b_set) {
                    items.push((format!("VM {:?} and {:?} use overlapping CPUs", a.id, b.id),
                        Risk::Scored(5, "CPU contention can delay either workload")));
                }
            }
            if let (Some(a_set), Some(b_set)) = (&a.memory_nodes, &b.memory_nodes) {
                if a_set.overlaps(b_set) {
                    items.push((format!("VM {:?} and {:?} use overlapping NUMA nodes", a.id, b.id),
                        Risk::Scored(4, "memory traffic can contend even when process memory is isolated")));
                }
            }
        }
    }
    for (i, driver) in plan.drivers.iter().enumerate() {
        let Some(attachment) = &driver.attachment else { continue };
        items.push((format!("Driver {:?} for VM {:?}, read-only sandbox {:?}", driver.id, attachment.vm, attachment.sandbox),
            Risk::Scored(7, "can execute a native process after admission with a separate identity, isolated network and no physical device access")));
        for other in &plan.drivers[..i] {
            if let Some(peer) = &other.attachment {
                if attachment.sandbox.starts_with(&peer.sandbox) || peer.sandbox.starts_with(&attachment.sandbox) {
                    items.push((format!("driver sandboxes {:?} and {:?} overlap", driver.id, other.id),
                        Risk::Scored(5, "providers may read common files from the operator's read-only driver root")));
                }
            }
        }
    }
    report.show("deployment configuration", items);
}

pub fn show_signature_exception(kind: Signature, id: &str, report: RiskReport) {
    let risk = match kind {
        Signature::Unsigned => Risk::Scored(9, "missing signature; the requested exception is bound to this artifact digest"),
        Signature::Invalid => Risk::Scored(10, "invalid signature; the requested exception is bound to this artifact digest"),
        Signature::Verified => return,
    };
    report.show("requested signature exception", [(format!("artifact {id:?}"), risk)]);
}

pub fn show_imports(vm: &str, result: ImportAssessment, report: RiskReport) {
    let mut unknown = Vec::new();
    match result {
        ImportAssessment::Complete { imports } => {
            println!("  VM {vm:?} has {} declared Wasm imports.", imports.len());
            for (namespace, name) in imports {
                let status = match namespace.as_str() {
                    "uwvm_ros_v2" => "ROSv2 host namespace; individual interface and resource decisions apply",
                    "uwvm_ros1_v1" | "uwvm_ros2_v1" if name == "abi_version" =>
                        "deprecated legacy ABI-version query; both an exact permission and a legacy-enabled VM build are required",
                    "wasi_snapshot_preview1" | "wasi_unstable" =>
                        "WASIp1 host namespace; only reviewed clock declarations are supported",
                    "wasi" if name == "thread-spawn" =>
                        "WASI Threads host namespace; this manifest cannot grant thread-spawn",
                    _ => {
                        let reason = "provider or host interface resolution requires VM admission";
                        unknown.push((format!("import {namespace:?} {name:?}"), Risk::Unassessed(reason)));
                        reason
                    }
                };
                println!("    imports {namespace:?} {name:?} — {status}");
            }
        }
        ImportAssessment::Unassessed { reason } => {
            println!("  VM {vm:?} Wasm imports unavailable: {reason}");
            unknown.push(("declared imports".into(), Risk::Unassessed(reason)));
        }
    }
    if !unknown.is_empty() {
        report.show(&format!("VM {vm:?} imports"), unknown);
    }
    println!("  Preloaded Wasm dependencies are not specified by this manifest format. Import declarations do not resolve dependency paths.");
}

pub fn confirm_deployment(action: &str, id: &str, digest: &str) -> Result<()> {
    let verb = if action == "authorize" { "authorize" } else { "deploy" };
    let answer = format!("{verb} {id}");
    eprint!("Confirm {id:?}, manifest SHA256 {digest}. Type {answer:?} to proceed: ");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let stdin = io::stdin();
    if read_answer(&mut stdin.lock())?.as_deref().map(str::trim) != Some(answer.as_str()) {
        return Err("deployment was not confirmed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_read_only_clock_from_control_and_unassessed() {
        for name in ["wasip1.clock_time_get", "wasip1.clock.monotonic-clock", "local/clock.ros/time/clock.read"] {
            assert!(matches!(permission_risk(name), Risk::Scored(0, _)), "{name}");
        }
        assert!(matches!(permission_risk("control.submit"), Risk::Scored(9, _)));
        assert!(matches!(permission_risk("context.open"), Risk::Unassessed(_)));
        assert!(matches!(permission_risk("wasip1.sock_open"), Risk::Unassessed(_)));
    }

    #[test]
    fn terminal_input_requires_a_complete_bounded_line() {
        assert_eq!(read_answer(&mut b"confirm\n".as_slice()).unwrap().as_deref(), Some("confirm\n"));
        assert!(read_answer(&mut b"confirm".as_slice()).unwrap().is_none());
        assert!(read_answer(&mut vec![b'a'; 1025].as_slice()).is_err());
    }
}
