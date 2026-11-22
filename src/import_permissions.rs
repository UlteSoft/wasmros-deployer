//! Compare a main image's static imports with the managed VM's effective interface settings.
use crate::guest_imports::ImportAssessment;
use crate::manifest::{hidden_key, Permission};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub struct Assessment {
    pub blocked: Vec<String>,
    pub warnings: Vec<String>,
    pub immutable_blocker: bool,
}

impl Assessment {
    fn unavailable(&mut self, message: String) {
        self.immutable_blocker = true;
        self.blocked.push(message);
    }

    pub fn show(&self, vm: &str, stage: &str) {
        for detail in &self.blocked { eprintln!("STARTUP BLOCKED for VM {vm:?} ({stage}): {detail}"); }
        for detail in &self.warnings { eprintln!("WARNING for VM {vm:?} ({stage}): {detail}"); }
    }

    pub fn ensure_linkable(&self, vm: &str) -> crate::manifest::Result<()> {
        if self.blocked.is_empty() { Ok(()) } else {
            Err(format!("VM {vm:?} has {} unresolved static import requirement(s); deployment cannot start", self.blocked.len()))
        }
    }
}

pub fn assess(inventory: &ImportAssessment, requires: &BTreeSet<String>, rights: &BTreeMap<String, bool>) -> Assessment {
    let mut result = Assessment::default();
    let ImportAssessment::Complete { imports } = inventory else {
        result.unavailable("the admitted image has no complete static import inventory".into());
        return result;
    };
    let mut imported = BTreeSet::new();
    let mut clock_active = false;
    let mut time_sources = 0;
    let mut resolution_sources = 0;
    for (key, enabled) in rights {
        match Permission::from_key(key) {
            Some(Permission::ClockInterface(_)) => clock_active = true,
            Some(Permission::ClockGrant(clock)) => {
                clock_active = true;
                if *enabled {
                    if clock.ends_with("-resolution") { resolution_sources += 1; } else { time_sources += 1; }
                }
            }
            _ => {}
        }
    }
    // A module can declare the same host import multiple times at the same type.
    let unique: BTreeSet<_> = imports.iter().map(|(ns, field)| (ns.as_str(), field.as_str())).collect();
    for (ns, field) in unique {
        let key = match ns {
            "uwvm_ros_v2" => field.to_owned(),
            "wasi_snapshot_preview1" => {
                let key = format!("wasip1.{field}");
                if !matches!(Permission::from_key(&key), Some(Permission::ClockInterface(_))) {
                    result.unavailable(format!("{ns:?}.{field:?} has no interface setting in the managed profile; rebuild the guest using a supported host import"));
                    continue;
                }
                key
            }
            "uwvm_ros1_v1" | "uwvm_ros2_v1" => format!("{ns}.{field}"),
            name if requires.contains(name) => continue, // The signed library linker checks its direct edge, field, kind and signature.
            name if crate::manifest::libraries::host_namespace(name) => {
                result.unavailable(format!("{ns:?}.{field:?} has no enabled provider in this managed launch profile"));
                continue;
            }
            _ => {
                result.unavailable(format!("no declared Wasm library provides {ns:?}.{field:?}; declare the direct <requires> edge and submit its matching library export or rebuild the guest"));
                continue;
            }
        };
        imported.insert(key.clone());
        let hidden = hidden_key(&key).is_some_and(|hide| rights.contains_key(hide));
        let bound_default = hidden_key(&key).is_some() && !hidden;
        match rights.get(&key).copied().or_else(|| bound_default.then_some(true)) {
            None => {
                let reason = match ns {
                    "wasi_snapshot_preview1" if !clock_active => "its Preview 1 namespace is disabled",
                    "uwvm_ros1_v1" | "uwvm_ros2_v1" => "its legacy namespace is disabled",
                    _ => "its exact interface is hidden",
                };
                let mut detail = format!("{ns:?}.{field:?} cannot link because {reason}. Enter 'allow {key}' to allow calls or 'deny {key}' to link with calls denied");
                if ns == "wasi_snapshot_preview1" {
                    let kind = if field.starts_with("clock_time_get") { "clock" } else { "resolution" };
                    detail.push_str(&format!(". Successful reads also require the selected source; for a monotonic source enter 'allow wasip1.clock.monotonic-{kind}'"));
                } else if matches!(field, "clock.create" | "clock.read" | "clock.update") {
                    detail.push_str(&format!(". Review a matching local clock and alias, for example 'allow local/clock.ros/ALIAS/{field}'"));
                } else if matches!(field, "driver.connect" | "driver.submit" | "driver.result" | "driver.disconnect") {
                    detail.push_str(". Review the declared driver's exact alias and 'allow driver/ALIAS/buffer.read'");
                }
                result.blocked.push(detail);
            }
            Some(false) => result.warnings.push(format!("{ns:?}.{field:?} can link; calls are explicitly denied by {key:?}")),
            Some(true) if ns == "wasi_snapshot_preview1" => {
                let (count, kind) = if field.starts_with("clock_time_get") { (time_sources,"clock") } else { (resolution_sources,"resolution") };
                if count == 0 {
                    result.warnings.push(format!("{key:?} can link, but all clock sources for this operation are denied. Review the clock ID used at call time; for a monotonic source enter 'allow wasip1.clock.monotonic-{kind}'"));
                } else if count < 4 {
                    result.warnings.push(format!("{key:?} can link with {count} of four source grants. Calls using other clock IDs are denied; the clock ID is a runtime argument"));
                }
            }
            _ => {}
        }
    }
    for name in &imported {
        if rights.get(name) != Some(&true) { continue; }
        let applicable = match name.as_str() {
            "clock.create" | "clock.read" | "clock.update" | "guard.create" | "guard.trigger" | "guard.take" |
            "timer.create" | "timer.reset" | "timer.cancel" | "timer.take" | "wait.create" | "wait.add" |
            "wait.remove" | "wait.acknowledge" | "wait.poll" => Some("local resource operation"),
            "vm.describe" | "module.describe" | "module.imports" | "module.exports" | "module.importers" |
            "module.group" | "module.permission.report" => Some("metadata target operation"),
            "driver.connect" | "driver.submit" | "driver.result" | "driver.disconnect" => Some("driver/ALIAS/buffer.read"),
            _ => None,
        };
        if let Some(kind) = applicable {
            let granted = rights.iter().any(|(key, enabled)| *enabled && match Permission::from_key(key) {
                Some(Permission::LocalOperation { operation, .. } | Permission::Metadata { operation, .. }) => operation == name,
                Some(Permission::DriverRead(_)) => name.starts_with("driver."),
                _ => false,
            });
            if !granted { result.warnings.push(format!("interface {name:?} can link, but there is no allowed {kind} that grants this operation; calls still require a matching resource")); }
        }
    }
    for (key, enabled) in rights {
        let Some(permission) = Permission::from_key(key) else { continue };
        let (target, direct) = match permission {
            Permission::RosInterface(_) | Permission::LegacyRosAbi { .. } | Permission::ClockInterface(_) => (key.as_str(), true),
            Permission::HideSelfReport => ("permission.report", true),
            Permission::HideAbi => ("abi", true),
            Permission::SelfReport(_) => ("permission.report", false),
            Permission::LocalOperation { operation, .. } | Permission::Metadata { operation, .. } => (operation, false),
            Permission::DriverRead(_) => {
                let matched = ["driver.submit", "driver.connect", "driver.result", "driver.disconnect"].into_iter().find(|op| imported.contains(*op));
                (matched.unwrap_or("driver.submit"), false)
            }
            Permission::ClockGrant(grant) => {
                let function = if grant.ends_with("-resolution") { "wasip1.clock_res_get" } else { "wasip1.clock_time_get" };
                let wide = format!("{function}_wasm64");
                if imported.contains(function) || imported.contains(&wide) {
                    if !*enabled { result.warnings.push(format!("clock grant {key:?} explicitly denies that source for {function}; the selected clock ID is known at call time")); }
                    continue;
                }
                (function, false)
            }
        };
        if imported.contains(target) {
            if !direct && !*enabled {
                result.warnings.push(format!("resource/selector decision {key:?} explicitly denies this selection for the imported operation {target:?}; its actual target is selected at call time"));
            }
            continue;
        }
        let access = match permission {
            Permission::HideSelfReport | Permission::HideAbi => "hidden restriction",
            _ if *enabled => "allow",
            _ => "deny restriction",
        };
        result.warnings.push(if direct {
            format!("explicit {access} for {key:?}: the main image has no static import of this interface")
        } else {
            format!("explicit {access} for {key:?}: the main image has no static import of the corresponding operation {target:?}; resource selection is a runtime decision")
        });
    }
    result
}
