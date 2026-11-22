//! Closed, per-VM Wasm dependency graphs. Names resolve only to submitted images.
use super::{attr, attributes, path, Result};
use roxmltree::Node;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::PathBuf;

pub const MAX_LIBRARIES: usize = 32;
pub const MAX_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Library {
    pub namespace: String,
    pub module_id: String,
    pub module: PathBuf,
    pub digest: String,
    pub policy: PathBuf,
    pub vm_policy: PathBuf,
    pub requires: BTreeSet<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Libraries {
    pub requires: BTreeSet<String>,
    /// Providers precede consumers. This also fixes the private guest filenames.
    pub ordered: Vec<Library>,
}

pub fn identifier(value: &str) -> bool {
    (1..=255).contains(&value.len())
        && value.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

pub(crate) fn host_namespace(name: &str) -> bool {
    name == "wasi" || name.starts_with("wasi_") || name.starts_with("wasi:")
        || name.starts_with("uwvm_") || name.starts_with("uwvm:")
        || matches!(name, "wros_deployer" | "wros.deployer") || name.starts_with("wros:")
}

fn edge(node: Node, requires: &mut BTreeSet<String>) -> Result<()> {
    attributes(node, "requires", &["module"])?;
    let name = attr(node, "module")?;
    if node.children().any(|child| child.is_element()) || !identifier(name)
        || host_namespace(name) || !requires.insert(name.to_owned()) || requires.len() > MAX_LIBRARIES
    {
        return Err("invalid, reserved or duplicate Wasm dependency edge".into());
    }
    Ok(())
}

impl Libraries {
    pub(super) fn parse(vm: Node, main_name: &str, main_image: &std::path::Path) -> Result<Self> {
        let mut graph = Self::default();
        let mut pending = BTreeMap::new();
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::from([main_image.to_owned()]);
        for node in vm.children().filter(Node::is_element) {
            if node.tag_name().name() == "requires" {
                edge(node, &mut graph.requires)?;
                continue;
            }
            attributes(node, "library", &["module-id", "namespace", "module", "sha256", "policy", "vm-policy"])?;
            let namespace = attr(node, "namespace")?;
            let module_id = attr(node, "module-id")?;
            let digest = attr(node, "sha256")?;
            let module = path(attr(node, "module")?)?;
            if pending.len() >= MAX_LIBRARIES
                || !identifier(namespace) || namespace.starts_with('-') || host_namespace(namespace)
                || namespace == main_name || !identifier(module_id) || !ids.insert(module_id)
                || !paths.insert(module.clone()) || digest.len() != 64
                || !digest.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            {
                return Err("invalid or conflicting Wasm library identity, namespace, path or digest".into());
            }
            let mut requires = BTreeSet::new();
            for child in node.children().filter(Node::is_element) {
                edge(child, &mut requires)?;
            }
            let lib = Library {
                namespace: namespace.into(), module_id: module_id.into(), module, digest: digest.into(),
                policy: path(attr(node, "policy")?)?, vm_policy: path(attr(node, "vm-policy")?)?, requires,
            };
            if pending.insert(namespace.to_owned(), lib).is_some() {
                return Err("duplicate Wasm library namespace".into());
            }
        }
        fn visit(name: &str, all: &mut BTreeMap<String, Library>, active: &mut BTreeSet<String>,
                 done: &mut BTreeSet<String>, ordered: &mut Vec<Library>) -> Result<()> {
            if done.contains(name) { return Ok(()); }
            if !active.insert(name.to_owned()) { return Err(format!("cyclic Wasm library dependency at {name:?}")); }
            let lib = all.remove(name).ok_or_else(|| format!("undeclared Wasm library {name:?}"))?;
            for dep in &lib.requires { visit(dep, all, active, done, ordered)?; }
            active.remove(name);
            done.insert(name.to_owned());
            ordered.push(lib);
            Ok(())
        }
        let mut active = BTreeSet::new();
        let mut done = BTreeSet::new();
        for name in &graph.requires { visit(name, &mut pending, &mut active, &mut done, &mut graph.ordered)?; }
        if !pending.is_empty() { return Err("unreachable Wasm library declaration".into()); }
        Ok(graph)
    }
}

pub fn image_path(index: usize) -> String { format!("/tmp/wros-library-{index}.wasm") }

/// Check the byte budget against the same immutable files that will be linked.
pub fn image_budget(main: &File, libraries: &[crate::verification::FrozenFile]) -> Result<()> {
    if libraries.len() > MAX_LIBRARIES { return Err("too many Wasm libraries".into()); }
    let mut total = main.metadata().map_err(|e| e.to_string())?.len();
    for image in libraries {
        total = total.checked_add(image.0.metadata().map_err(|e| e.to_string())?.len())
            .ok_or("Wasm library image budget overflow")?;
    }
    if total > MAX_IMAGE_BYTES { return Err("main image and Wasm libraries exceed 256 MiB".into()); }
    Ok(())
}

#[cfg(feature = "recovery-preflight")]
pub fn link(main: &File, graph: &Libraries, libraries: &[crate::verification::FrozenFile]) -> Result<()> {
    use std::os::unix::fs::FileExt;
    use wasmparser::{types::EntityType, FuncType, ValType, Validator, WasmFeatures};

    type Exports = BTreeMap<String, FuncType>;
    fn assess(image: &File, requires: &BTreeSet<String>, main: bool, providers: &BTreeMap<&str, Exports>) -> Result<Exports> {
        let size = image.metadata().map_err(|e| e.to_string())?.len();
        let mut bytes = vec![0; usize::try_from(size).map_err(|_| "Wasm image too large")?];
        image.read_exact_at(&mut bytes, 0).map_err(|e| e.to_string())?;
        if !bytes.starts_with(b"\0asm\x01\0\0\0") { return Err("library graphs require WebAssembly core modules".into()); }
        // A shared linear memory or shared reference is outside this ABI even when it is internal.
        let features = WasmFeatures::default() - WasmFeatures::THREADS - WasmFeatures::SHARED_EVERYTHING_THREADS;
        let types = Validator::new_with_features(features).validate_all(&bytes)
            .map_err(|e| format!("unsupported Wasm library graph module: {e}"))?;
        let module = types.as_ref();
        let scalar_fn = |entity| {
            let EntityType::Func(id) = entity else { return None; };
            let ty = types[id].unwrap_func();
            (ty.params().len() + ty.results().len() <= 256
                && ty.params().iter().chain(ty.results()).all(|v| matches!(v, ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64)))
                .then_some(ty)
        };
        let mut seen = BTreeSet::new();
        let mut name_bytes = 0;
        let mut fields = BTreeSet::new();
        for (i, (namespace, field, entity)) in module.core_imports().ok_or("expected core imports")?.enumerate() {
            name_bytes += namespace.len() + field.len();
            if i >= 2048 || name_bytes > 65536 { return Err("Wasm library import inventory exceeds budget".into()); }
            crate::guest_imports::check_host_import(namespace, field)?;
            if host_namespace(namespace) {
                if !main { return Err(format!("Wasm library host import {namespace:?}.{field:?} is denied")); }
                // Existing per-main review covers the host interfaces it can actually configure.
                if !matches!(namespace, "wasi_snapshot_preview1" | "wasi_unstable" | "uwvm_ros_v2" | "uwvm_ros1_v1" | "uwvm_ros2_v1")
                    || !matches!(entity, EntityType::Func(_)) {
                    return Err(format!("unsupported host import {namespace:?}.{field:?} in Wasm library graph"));
                }
                continue;
            }
            let problem = |reason: &str| format!("unapproved or incompatible Wasm function import {namespace:?}.{field:?}: {reason}");
            if !fields.insert((namespace, field)) { return Err(problem("duplicate function import in the scalar library graph")); }
            if !requires.contains(namespace) { return Err(problem("calling module is missing its direct requires edge")); }
            let exports = providers.get(namespace).ok_or_else(|| problem("no submitted provider for this namespace"))?;
            let requested = scalar_fn(entity).ok_or_else(|| problem("requested import is outside the scalar function ABI"))?;
            let offered = exports.get(field).ok_or_else(|| problem("provider has no scalar function export with this name"))?;
            if requested != offered { return Err(problem("provider export has a different function signature")); }
            seen.insert(namespace.to_owned());
        }
        if &seen != requires { return Err("Wasm dependency declarations differ from actual static imports".into()); }
        let mut exports = Exports::new();
        if !main {
            for (i, (field, entity)) in module.core_exports().ok_or("expected core exports")?.enumerate() {
                name_bytes += field.len();
                if i >= 2048 || name_bytes > 65536 { return Err("Wasm library export inventory exceeds budget".into()); }
                if let Some(ty) = scalar_fn(entity) {
                    exports.insert(field.to_owned(), ty.clone());
                }
            }
        }
        Ok(exports)
    }
    if graph.ordered.len() != libraries.len() { return Err("incomplete Wasm library image set".into()); }
    image_budget(main, libraries)?;
    let mut providers = BTreeMap::new();
    for (lib, file) in graph.ordered.iter().zip(libraries) {
        let exports = assess(&file.0, &lib.requires, false, &providers)
            .map_err(|e| format!("Wasm library {:?}: {e}", lib.namespace))?;
        providers.insert(lib.namespace.as_str(), exports);
    }
    assess(main, &graph.requires, true, &providers)?;
    Ok(())
}

#[cfg(not(feature = "recovery-preflight"))]
pub fn link(_: &File, _: &Libraries, _: &[crate::verification::FrozenFile]) -> Result<()> {
    Err("Wasm library graphs require the core Wasm validator in this build".into())
}
