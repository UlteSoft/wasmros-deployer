//! Admit the entire same-VM import closure before operator review.
use crate::review::{self, RiskReport};
use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use wros_deployer::{manifest::{libraries, local_file, Process, Result}, supervisor, verification, verdict::Signature};

#[derive(Default)]
pub struct Prepared {
    pub images: Vec<verification::FrozenFile>,
    pub waivers: BTreeMap<String, Signature>,
    pub argv: Vec<String>,
}

pub fn prepare(
    vm: &Process, main: &File, bundle: &File, root: &Path, policies: &Path,
    verifier: Option<(&PathBuf, &PathBuf)>, executing: bool,
    exceptions: &BTreeMap<String, (String, Signature)>, risk: RiskReport,
) -> Result<Prepared> {
    let mut prepared = Prepared::default();
    if vm.libraries.ordered.is_empty() { return Ok(prepared); }
    let mut total = main.metadata().map_err(|e| e.to_string())?.len();
    for (index, lib) in vm.libraries.ordered.iter().enumerate() {
        let item = format!("{}/{}", vm.id, lib.namespace);
        let primary = verification::policy(policies, &lib.policy, root)?;
        let secondary = verification::policy(policies, &lib.vm_policy, root)?;
        verification::equivalent_vm_policy(&primary, &secondary)?;
        let file = local_file(bundle, &lib.module)?;
        let remaining = libraries::MAX_IMAGE_BYTES.checked_sub(total).ok_or("Wasm image budget overflow")?;
        if file.metadata().map_err(|e| e.to_string())?.len() > remaining {
            return Err("main image and Wasm libraries exceed 256 MiB".into());
        }
        let mut signed = true;
        let image = if let Some((exe, scratch)) = verifier {
            let admission = verification::admit_image(exe, scratch, root, file, &lib.digest, &primary, Some(&lib.module_id))
                .map_err(|e| format!("Wasm library {item:?}: {e}"))?;
            if admission.signature != Signature::Verified {
                if !exceptions.get(&item).is_some_and(|(digest, kind)| digest == &lib.digest && *kind == admission.signature) {
                    return Err(format!("{:?} signature rejected for Wasm library {item:?}", admission.signature));
                }
                signed = false;
                prepared.waivers.insert(lib.namespace.clone(), admission.signature);
                review::show_signature_exception(admission.signature, &item, risk);
                eprintln!("WARNING: {:?} Wasm library admitted by explicit exception for {item:?} at SHA256 {}", admission.signature, lib.digest);
            } else {
                println!("INFO WSEA policy and signed module-id {:?} verified for Wasm library {item:?}", lib.module_id);
            }
            admission.module
        } else {
            verification::snapshot_for_review(file, &lib.digest)?
        };
        let size = image.0.metadata().map_err(|e| e.to_string())?.len();
        if size > remaining {
            return Err("admitted main image and Wasm libraries exceed 256 MiB".into());
        }
        total += size;
        // Retain above stdio so redirection during exec cannot replace a pinned image.
        prepared.images.push(if executing { verification::FrozenFile(supervisor::retained(image.0)?) } else { image });
        let path = if executing { libraries::image_path(index) } else { root.join(&lib.module).display().to_string() };
        if signed {
            prepared.argv.extend(["--secure".into(), "named-module".into(), path.clone(),
                secondary.display().to_string(), lib.module_id.clone()]);
        }
        prepared.argv.extend(["--wasm-preload-library".into(), path, lib.namespace.clone()]);
        println!("INFO Wasm library {item:?}, signed identity {:?}, SHA256 {}, dependencies {:?}, effective host permissions: none; only declared scalar function links.",
                 lib.module_id, lib.digest, lib.requires);
    }
    libraries::link(main, &vm.libraries, &prepared.images).map_err(|e| format!("STARTUP BLOCKED for VM {:?}: {e}", vm.id))?;
    println!("INFO VM {:?} Wasm library closure validated against all actual import namespaces, fields and function signatures.", vm.id);
    if !executing { prepared.images.clear(); }
    Ok(prepared)
}
