//! File-backed regressions for dependency discovery before permission review.
use std::fs::{self, File};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use wros_deployer::manifest::{bundle::{Bundle, Kind}, deployment, recommendations};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static ID: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".tmp");
        fs::create_dir_all(&root).unwrap();
        let directory = root.join(format!("xml-closure-{}-{}", std::process::id(), ID.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    fn put(&self, filename: &str, contents: &str) {
        let path = self.0.join(filename);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    fn root(&self) -> File { File::open(&self.0).unwrap() }
}
impl Drop for Fixture {
    fn drop(&mut self) { fs::remove_dir_all(&self.0).unwrap(); }
}
fn vm(id: &str) -> String {
    format!(r#"<vm id="{id}" module="{id}.wasm" sha256="{}" policy="trust" memory-bytes="134217728" pids="4"/>"#, "0".repeat(64))
}
fn include(file: &str) -> String { format!(r#"<include file="{file}"/>"#) }
fn fragment(body: &str) -> String { format!("<deployment-fragment>{body}</deployment-fragment>") }
fn plan(body: &str) -> String { format!(r#"<deployment id="cell">{body}</deployment>"#) }

#[test]
fn resolves_a_diamond_once_and_binds_the_original_inputs() {
    let f = Fixture::new();
    f.put("root.xml", &plan(&(include("parts/left.xml") + &include("right.xml"))));
    f.put("parts/left.xml", &fragment(&(include("parts/shared.xml") + &vm("left"))));
    f.put("right.xml", &fragment(&(include("parts/shared.xml") + &vm("right"))));
    f.put("parts/shared.xml", &fragment(&vm("shared")));
    let dir = f.root();
    let mut bundle = Bundle::new(&dir);
    let graph = bundle.expand(Path::new("root.xml"), Kind::Deployment).unwrap();
    let parsed = deployment(&graph.xml).unwrap();
    assert_eq!(parsed.processes.iter().map(|p|p.id.as_str()).collect::<Vec<_>>(), ["shared","left","right"]);
    assert_eq!(graph.inputs.len(), 4);
    bundle.revalidate().unwrap();
    f.put("right.xml", &(fragment(&(include("parts/shared.xml") + &vm("right"))) + "\n"));
    assert!(bundle.revalidate().is_err());
    let new = Bundle::new(&dir).expand(Path::new("root.xml"), Kind::Deployment).unwrap();
    assert_ne!(new.digest, graph.digest);
    assert_eq!(new.xml, graph.xml);
}

#[test]
fn resolves_permission_files_per_vm_and_rejects_competing_decisions() {
    let f = Fixture::new();
    f.put("a.xml", "<recommendations><include file='shared.xml'/><interface name='type.describe' expose='deny'/></recommendations>");
    f.put("b.xml", "<recommendations><include file='shared.xml'/></recommendations>");
    f.put("shared.xml", "<recommendations><interface name='abi' expose='allow'/></recommendations>");
    let dir = f.root();
    let mut bundle = Bundle::new(&dir);
    let read = |bundle: &mut Bundle<'_>, name| recommendations(&bundle.expand(Path::new(name), Kind::Recommendations)?.xml);
    assert_eq!(read(&mut bundle, "a.xml").unwrap().len(), 2);
    assert_eq!(read(&mut bundle, "b.xml").unwrap().len(), 1);
    f.put("dup.xml", "<recommendations><include file='shared.xml'/><interface name='abi' expose='deny'/></recommendations>");
    assert!(read(&mut bundle, "dup.xml").is_err());
}

#[test]
fn rejects_cycles_missing_paths_symlinks_and_wrong_document_kinds() {
    let f = Fixture::new();
    let dir = f.root();
    for (child, contents) in [
        ("root.xml", None),
        ("absent.xml", None),
        ("../outside.xml", None),
        ("/etc/passwd", None),
        ("https://invalid", None),
        ("wrong.xml", Some("<recommendations/>")),
        ("nested.xml", Some("<deployment-fragment><supervisor/></deployment-fragment>")),
        ("namespaced.xml", Some("<deployment-fragment xmlns='unregistered'/>")),
        ("nested-include.xml", Some("<deployment-fragment><include file='leaf'><vm/></include></deployment-fragment>")),
        ("two.xml", Some("<deployment-fragment><include file='root.xml'/></deployment-fragment>")),
    ] {
        f.put("root.xml", &plan(&include(child)));
        if let Some(text) = contents { f.put(child,text); }
        assert!(Bundle::new(&dir).expand(Path::new("root.xml"),Kind::Deployment).is_err(), "{child}");
    }
    f.put("real.xml", &fragment(&vm("simple")));
    symlink("real.xml", f.0.join("alias.xml")).unwrap();
    f.put("root.xml",&plan(&include("alias.xml")));
    assert!(Bundle::new(&dir).expand(Path::new("root.xml"),Kind::Deployment).is_err());
}

#[test]
fn rejects_excess_depth_duplicate_processes_and_flag_like_ids() {
    let f = Fixture::new();
    let dir = f.root();
    f.put("root.xml",&plan(&include("1.xml")));
    for n in 1..20 { f.put(&format!("{n}.xml"),&fragment(&include(&format!("{}.xml",n+1)))); }
    f.put("20.xml",&fragment(&vm("last")));
    assert!(Bundle::new(&dir).expand(Path::new("root.xml"),Kind::Deployment).is_err());
    f.put("1.xml", &fragment(&vm("same")));
    f.put("root.xml", &plan(&(include("1.xml") + &vm("same"))));
    let graph = Bundle::new(&dir).expand(Path::new("root.xml"),Kind::Deployment).unwrap();
    assert!(deployment(&graph.xml).is_err());
    assert!(deployment(&plan(&vm("--switch"))).is_err());
}
