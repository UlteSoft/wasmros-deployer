use wros_deployer::manifest::{deployment,recommendations};
fn config()->String {
    format!(r#"<deployment id="cell"><vm id="body" module="main.wasm" sha256="{}" policy="trust.xml" memory-bytes="134217728" pids="8"/></deployment>"#,"a".repeat(64))
}
#[test] fn zero_implicit_grants(){let p=deployment(&config()).unwrap();assert!(p.processes[0].recommendations.is_none())}
#[test] fn reject_nested_or_unknown_and_escaping_paths(){
    for bad in [config().replace("main.wasm","../other"),config().replace("pids=","pidz="),config().replace("id=\"cell\"","xmlns=\"other\" id=\"cell\""),config().replace("/></deployment>","><recommendations/></vm></deployment>"),format!("<!DOCTYPE x [<!ENTITY test 'a'>]>{}",config())]{
        assert!(deployment(&bad).is_err(),"{bad}");
    }
}
#[test] fn recommendation_is_separate_and_unique(){
    assert!(recommendations(&config()).is_err());
    let point=r#"<interface name="driver.connect" expose="deny"/>"#;
    assert!(!recommendations(&format!("<recommendations>{point}</recommendations>")).unwrap()["driver.connect"]);
    assert!(recommendations(&format!("<recommendations>{point}{point}</recommendations>")).is_err());
}
