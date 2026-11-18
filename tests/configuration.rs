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
