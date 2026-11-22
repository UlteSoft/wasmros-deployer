use wros_deployer::manifest::{deployment, recommendations};
fn config() -> String {
    format!(
        r#"<deployment id="cell"><vm id="body" module="main.wasm" sha256="{}" policy="trust.xml" memory-bytes="134217728" pids="8"/></deployment>"#,
        "a".repeat(64)
    )
}
#[test]
fn zero_implicit_grants() {
    let p = deployment(&config()).unwrap();
    assert!(p.processes[0].recommendations.is_none())
}
#[test]
fn reviewed_engine_uses_one_fixed_vm_argument() {
    for (field, expected) in [
        ("", "--runtime-aot"),
        ("engine=\"aot\"", "--runtime-aot"),
        ("engine=\"interpreter\"", "--runtime-int"),
    ] {
        let xml = config().replace("pids=", &format!("{field} pids="));
        assert_eq!(deployment(&xml).unwrap().processes[0].engine.argument(), expected);
    }
    for invalid in ["", "auto", "--runtime-int", "aot --runtime-disable-memtag"] {
        let xml = config().replace("pids=", &format!("engine=\"{invalid}\" pids="));
        assert!(deployment(&xml).is_err());
    }
}
#[test]
fn reject_nested_or_unknown_and_escaping_paths() {
    for bad in [
        config().replace("main.wasm", "../other"),
        config().replace("pids=", "pidz="),
        config().replace("id=\"cell\"", "xmlns=\"other\" id=\"cell\""),
        config().replace("/></deployment>", "><recommendations/></vm></deployment>"),
        format!("<!DOCTYPE x [<!ENTITY test 'a'>]>{}", config()),
    ] {
        assert!(deployment(&bad).is_err(), "{bad}");
    }
}
#[test]
fn recommendation_is_separate_and_unique() {
    assert!(recommendations(&config()).is_err());
    let point = r#"<interface name="driver.connect" expose="deny"/>"#;
    assert!(
        !recommendations(&format!("<recommendations>{point}</recommendations>")).unwrap()
            ["driver.connect"]
    );
    assert!(recommendations(&format!(
        "<recommendations>{point}{point}</recommendations>"
    ))
    .is_err());
}

#[test]
fn native_attachment_requires_distinct_identity_and_read_review() {
    let attachment = format!(
        r#"<attachment vm="body" alias="telemetry" sandbox="go2" uid="24002" gid="24002" contract-sha256="{}" memory-bytes="134217728" pids="8" cpu-micros="100000"/>"#,
        "b".repeat(64),
    );
    let driver = format!(
        r#"<driver id="driver1" file="native.elf" sha256="{}" kind="executable" vendor-version="1" hardware-id="probe" elf-signer="vendor.pem">{attachment}</driver>"#,
        "c".repeat(64),
    );
    let xml = config().replace("pids=", r#"uid="24001" gid="24001" pids="#)
        .replace("</deployment>", &format!("{driver}</deployment>"));
    let plan = deployment(&xml).unwrap();
    let native = plan.drivers[0].attachment.as_ref().unwrap();
    assert_eq!(native.vm, "body");
    assert_eq!(native.identity, (24002, 24002));
    assert_eq!(native.request_millis, 2000);
    for invalid in [
        xml.replace(r#"uid="24002""#, r#"uid="24001""#),
        xml.replace(r#"gid="24002""#, r#"gid="0""#),
        xml.replace(r#"vm="body""#, r#"vm="absent""#),
        xml.replace(r#"sandbox="go2""#, r#"sandbox="../go2""#),
        xml.replace(r#"kind="executable""#, r#"kind="shared-library""#),
        xml.replace(r#"sandbox="go2""#, r#"sandbox="go2" request-millis="180001""#),
    ] {
        assert!(deployment(&invalid).is_err(), "{invalid}");
    }
    let grants = r#"<recommendations><driver-resource alias="telemetry" operation="buffer.read" access="allow"/></recommendations>"#;
    let rights = recommendations(grants).unwrap();
    assert_eq!(rights.get("driver/telemetry/buffer.read"), Some(&true));
    assert!(recommendations(&grants.replace("buffer.read", "buffer.write")).is_err());
}

#[test]
fn bundle_reads_regular_files_through_the_pinned_directory() {
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    use std::path::Path;
    use wros_deployer::manifest::{local_file, read_xml, xml_contents};

    let directory = std::env::temp_dir().join(format!("wros-bundle-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let root = File::open(&directory).unwrap();
    let nested = directory.join("submitted");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("deployment.xml"), config()).unwrap();
    let document = local_file(&root, Path::new("submitted/deployment.xml")).unwrap();
    assert_eq!(xml_contents(document).unwrap(), config());

    symlink("submitted", directory.join("alias")).unwrap();
    symlink("submitted/deployment.xml", directory.join("linked.xml")).unwrap();
    let pipe = CString::new(directory.join("pipe.xml").as_os_str().as_bytes()).unwrap();
    // The fixture is a FIFO with no writer. A type check must finish immediately.
    assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
    for path in ["submitted", "alias/deployment.xml", "linked.xml", "pipe.xml"] {
        assert!(local_file(&root, Path::new(path)).is_err(), "{path}");
    }
    assert!(read_xml(&directory.join("pipe.xml")).is_err());
    assert!(read_xml(Path::new("/dev/null")).is_err());
    fs::remove_dir_all(directory).unwrap();
}
#[test]
fn bounded_restart_and_nonroot_identity() {
    for attributes in [
        "uid=\"0\" gid=\"1\"",
        "uid=\"1\"",
        "restart-limit=\"33\"",
        "restart-delay-ms=\"0\"",
        "cpu-micros=\"0\"",
        "uid=\"4294967295\" gid=\"1\"",
    ] {
        assert!(deployment(&config().replace("pids=", &format!("{attributes} pids="))).is_err());
    }
    let parsed =
        deployment(&config().replace("pids=", "uid=\"10001\" gid=\"10001\" pids=")).unwrap();
    assert_eq!(parsed.processes[0].identity, Some((10001, 10001)));
    assert_eq!(parsed.processes[0].restart_limit, 3);
}
#[test]
fn vm_instances_cannot_share_host_identity() {
    let xml = config().replace("pids=", "uid=\"10001\" gid=\"10001\" pids=");
    let first = xml
        .strip_prefix("<deployment id=\"cell\">")
        .unwrap()
        .strip_suffix("</deployment>")
        .unwrap();
    let second = first.replace("id=\"body\"", "id=\"other\"");
    assert!(deployment(&format!(
        "<deployment id=\"cell\">{first}{second}</deployment>"
    ))
    .is_err());
}

#[test]
fn placement_is_explicit_and_rejects_ambiguous_lists() {
    let parsed = deployment(&config()).unwrap();
    assert!(parsed.processes[0].cpus.is_none());
    assert!(parsed.processes[0].memory_nodes.is_none());
    let xml = config().replace("pids=", "cpus=\"0,1-3,8\" memory-nodes=\"1\" pids=");
    let parsed = deployment(&xml).unwrap();
    assert_eq!(
        parsed.processes[0].cpus.as_ref().unwrap().to_string(),
        "0-3,8"
    );
    assert_eq!(
        parsed.processes[0]
            .memory_nodes
            .as_ref()
            .unwrap()
            .to_string(),
        "1"
    );
    for attributes in [
        "cpus=\"\"",
        "cpus=\"2,1\"",
        "memory-nodes=\"8192\"",
        "memory-nodes=\"-1\"",
    ] {
        assert!(deployment(&config().replace("pids=", &format!("{attributes} pids="))).is_err());
    }
}

#[test]
fn manager_budget_is_separate_and_cannot_overflow() {
    use wros_deployer::service;
    let raw = config().replace("pids=", "uid=\"10001\" gid=\"10001\" pids=");
    assert!(service::budget(&deployment(&raw).unwrap()).is_err());
    let manager =
        "<supervisor memory-bytes=\"268435456\" pids=\"64\" cpu-micros=\"50000\" cpus=\"0\"/>";
    let xml = raw.replace("<vm", &format!("{manager}<vm"));
    let parsed = deployment(&xml).unwrap();
    let b = service::budget(&parsed).unwrap();
    assert_eq!(b.workload_memory, 134217728);
    assert_eq!(b.memory, 134217728 + 268435456 + 4 * 1024 * 1024);
    assert_eq!(b.tasks, 8 + 64 + 4);
    for bad in [
        xml.replace(manager, &format!("{manager}{manager}")),
        xml.replace("268435456", "1"),
        xml.replace("pids=\"64\"", "pids=\"0\""),
        xml.replace("cpu-micros=\"50000\"", "cpu-micros=\"0\""),
        xml.replace("cpus=\"0\"", "cpus=\"2,1\""),
        xml.replace("<supervisor ", "<supervisor unknown=\"true\" "),
    ] {
        assert!(deployment(&bad).is_err(), "{bad}");
    }
    assert!(service::budget(
        &deployment(&xml.replace("268435456", "18446744073709551615")).unwrap()
    )
    .is_err());
}

#[test]
fn clock_import_and_read_authority_are_independent() {
    let rights = recommendations(r#"<recommendations>
        <interface name="abi" expose="allow"/>
        <interface name="wasip1.clock_time_get_wasm64" expose="deny"/>
        <wasip1-clock name="monotonic-clock" access="allow"/>
        <wasip1-clock name="process-resolution" access="deny"/>
        </recommendations>"#).unwrap();
    assert_eq!(rights.len(), 4);
    assert!(rights["abi"]);
    assert!(!rights["wasip1.clock_time_get_wasm64"]);
    assert!(rights["wasip1.clock.monotonic-clock"]);
    assert!(!rights["wasip1.clock.process-resolution"]);
    for bad in [
        r#"<interface name="wasip1.clock.monotonic-clock" expose="allow"/>"#,
        r#"<interface name="wasip1.sock_open" expose="allow"/>"#,
        r#"<wasip1-clock name="clock_time_get" access="allow"/>"#,
        r#"<wasip1-clock name="monotonic-timer" access="allow"/>"#,
        r#"<wasip1-clock name="realtime-clock" expose="allow"/>"#,
        r#"<wasip1-clock name="realtime-clock" access="allow"/><wasip1-clock name="realtime-clock" access="deny"/>"#,
    ] {
        assert!(recommendations(&format!("<recommendations>{bad}</recommendations>")).is_err(), "{bad}");
    }
}

#[test]
fn aot_policy_is_scoped_to_the_aot_engine() {
    assert!(deployment(&config()).unwrap().processes[0].aot_policy.is_none());
    for policy in ["default", "fast-compile", "balanced", "max"] {
        let xml = config().replace("pids=", &format!(r#"aot-policy="{policy}" pids="#));
        assert_eq!(deployment(&xml).unwrap().processes[0].aot_policy, Some(policy));
        assert!(deployment(&xml.replace("pids=", r#"engine="interpreter" pids="#)).is_err());
    }
    assert!(deployment(&config().replace("pids=", r#"aot-policy="unknown" pids="#)).is_err());
}

#[test]
fn local_scheduling_actions_bind_one_vm_alias() {
    use wros_deployer::manifest::{reviewed_grants, Permission};
    let xml = r#"<recommendations>
        <local-resource type="guard" alias="signal" operation="guard.create" access="allow"/>
        <local-resource type="guard" alias="signal" operation="guard.take" access="deny"/>
        <local-resource type="guard" alias="other" operation="guard.trigger" access="deny"/>
        <interface name="guard.take" expose="allow"/>
    </recommendations>"#;
    let rights = recommendations(xml).unwrap();
    let grants = reviewed_grants(&rights).unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants["signal"].kind, "guard");
    assert_eq!(grants["signal"].operations, ["guard.create"]);
    for invalid in [
        xml.replace("alias=\"other\"", "alias=\"signal\" type=\"wait\""),
        xml.replace("type=\"guard\" alias=\"other\" operation=\"guard.trigger\"", "type=\"wait\" alias=\"signal\" operation=\"wait.poll\""),
        xml.replace("guard.create", "clock.update"),
        xml.replace("type=\"guard\"", "type=\"driver\""),
        xml.replace("alias=\"signal\"", "alias=\"--run\""),
        xml.replace("operation=\"guard.create\"", "operation=\"guard.create,guard.trigger\""),
        xml.replace("name=\"guard.take\"", "name=\"local/guard/signal/guard.take\""),
    ] {
        assert!(recommendations(&invalid).is_err());
    }
    for key in ["local/clock.system/c/clock.update", "local/clock.steady/c/clock.update",
                "local/guard/a/b/guard.create", "local/timer/t/wait.poll", "local/clock.ros//clock.read"] {
        assert!(Permission::from_key(key).is_none());
    }
}

#[test]
fn report_visibility_and_foreign_metadata_are_independent() {
    use wros_deployer::manifest::{reviewed_grants, Permission};
    let xml = r#"<recommendations>
      <self-report selector="wasip1.fd_write" access="deny"/>
      <self-report selector="preloadwasm" access="allow"/>
      <metadata type="module" alias="observer" target="worker" operation="module.exports" access="allow"/>
      <metadata type="module" alias="observer" target="worker" operation="module.importers" access="deny"/>
      <metadata type="vm" alias="host" target="runtime" operation="vm.describe" access="allow"/>
    </recommendations>"#;
    let rights = recommendations(xml).unwrap();
    let grants = reviewed_grants(&rights).unwrap();
    assert_eq!(grants.len(), 2);
    assert_eq!(grants["observer"].operations, ["module.exports"]);
    assert_eq!(grants["observer"].target, "worker");
    assert_eq!(grants["host"].binding, "metadata");
    assert!(!rights["report/wasip1.fd_write"]);
    for s in ["rosv2.", "*", "vm", "rosv2..", "rosv2...", "bad.fd_write", "rosv2.*", "wasip1.fd/write"] {
        assert!(recommendations(&xml.replace("wasip1.fd_write", s)).is_err());
    }
    assert!(Permission::from_key(&format!("report/preloadwasm.{}", "x".repeat(255))).is_some());
    assert!(Permission::from_key(&format!("report/preloadwasm.{}", "x".repeat(256))).is_none());
    for bad in [xml.replace("vm.describe", "driver.submit"), xml.replace("runtime", "wrong"),
        xml.replace("module.importers", "capability.revoke"), xml.replace("host", "observer"),
        xml.replace(r#"target="worker" operation="module.exports""#, r#"target="other" operation="module.exports""#)] {
        assert!(recommendations(&bad).is_err());
    }
}
