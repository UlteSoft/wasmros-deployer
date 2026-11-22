use std::collections::{BTreeMap, BTreeSet};
use wros_deployer::{guest_imports::ImportAssessment, import_permissions::{assess, Assessment}};

fn compare(imports: &[(&str,&str)], rights: &[(&str,bool)]) -> Assessment {
    let inventory = ImportAssessment::Complete {
        imports: imports.iter().map(|(ns, field)| (ns.to_string(), field.to_string())).collect(),
    };
    let rights: BTreeMap<_,_> = rights.iter().map(|(key, enabled)| (key.to_string(), *enabled)).collect();
    assess(&inventory, &BTreeSet::new(), &rights)
}

#[test]
fn distinguishes_bound_defaults_hidden_imports_denied_calls_and_extra_restrictions() {
    let imports = [("uwvm_ros_v2", "abi"), ("uwvm_ros_v2", "permission.report"), ("uwvm_ros_v2", "clock.read")];
    let missing = compare(&imports, &[]);
    assert_eq!(missing.blocked.len(), 1);
    assert!(missing.blocked[0].contains("allow clock.read"));
    let reviewed = compare(&imports, &[("clock.read",false),("context.open",true),("driver.describe",false)]);
    assert!(reviewed.blocked.is_empty());
    assert!(reviewed.warnings.iter().any(|w| w.contains("calls are explicitly denied")));
    assert!(reviewed.warnings.iter().any(|w| w.contains("explicit allow") && w.contains("context.open")));
    assert!(reviewed.warnings.iter().any(|w| w.contains("deny restriction") && w.contains("driver.describe")));
    assert_eq!(compare(&imports, &[("hide/permission.report",true),("hide/abi",true),("clock.read",true)]).blocked.len(), 2);
    let extra = compare(&[], &[("hide/abi", true)]);
    assert!(extra.warnings[0].contains("hidden restriction"));
}

#[test]
fn uses_the_exact_preview1_namespace_interface_and_clock_source_family() {
    let imports = [("wasi_snapshot_preview1", "clock_time_get_wasm64")];
    let disabled = compare(&imports, &[]);
    assert!(disabled.blocked[0].contains("namespace is disabled"));
    let hidden = compare(&imports, &[("wasip1.clock.monotonic-clock",true)]);
    assert!(hidden.blocked[0].contains("exact interface is hidden"));
    let allowed = compare(&imports, &[("wasip1.clock_time_get_wasm64",true),("wasip1.clock.monotonic-resolution",true)]);
    assert!(allowed.blocked.is_empty());
    assert!(allowed.warnings.iter().any(|w| w.contains("all clock sources")));
    assert!(allowed.warnings.iter().any(|w| w.contains("monotonic-resolution") && w.contains("no static import")));
    let split = compare(&imports, &[("wasip1.clock_time_get_wasm64",true),("wasip1.clock.monotonic-clock",true),
                                  ("wasip1.clock.realtime-clock",false)]);
    assert!(split.warnings.iter().any(|w| w.contains("realtime-clock") && w.contains("denies that source")));
    for ns in ["wasi_unstable","wasi"] {
        assert!(compare(&[(ns,"clock_time_get")], &[("wasip1.clock_time_get",true)]).immutable_blocker);
    }
}

#[test]
fn unknown_providers_and_unavailable_interfaces_cannot_be_fixed_with_unrelated_grants() {
    for (ns, field) in [("peer","answer"),("wasi_snapshot_preview1","fd_write"),("wasi","thread-spawn")] {
        assert!(compare(&[(ns,field)], &[("abi",true)]).immutable_blocker);
    }
    let legacy = [("uwvm_ros1_v1", "abi_version"),("uwvm_ros2_v1", "abi_version")];
    let split = compare(&legacy, &[("uwvm_ros1_v1.abi_version",false)]);
    assert_eq!(split.blocked.len(), 1);
    assert!(split.blocked[0].contains("uwvm_ros2_v1"));
    assert!(split.warnings.iter().any(|w| w.contains("uwvm_ros1_v1") && w.contains("explicitly denied")));
}

#[test]
fn separately_reports_import_exposure_and_scope_of_resource_denial() {
    let imports = [("uwvm_ros_v2", "clock.read"),("uwvm_ros_v2", "module.describe"),
                   ("uwvm_ros_v2", "driver.submit"),("uwvm_ros_v2", "permission.report")];
    let rights = [("clock.read", true),("local/clock.steady/tick/clock.read", false),
                  ("metadata/module/state/other/module.describe",false),("module.describe",true),
                  ("driver/imu/buffer.read",false),("driver.submit",true),("report/preloaddl",false)];
    let checked = compare(&imports, &rights);
    assert!(checked.blocked.is_empty());
    for (key, allowed) in rights {
        if !allowed { assert!(checked.warnings.iter().any(|w| w.contains(key) && w.contains("this selection")), "{key}"); }
    }
}
