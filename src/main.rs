//! Local preflight and operator review for one fixed bundle.
use manifest::{deployment, local_file, read_xml, recommendations, sha256, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use wros_deployer::{manifest, state, supervisor, verdict::Signature, verification};

/// Bind every automatic invocation to the exact reviewed configuration and
/// executable/trust-policy bytes. Recommendation files are not read on resume:
/// the independently reviewed permission map is stored in the protected record.
fn binding(
    xml: &str,
    manifest: &std::path::Path,
    plan: &manifest::Deployment,
    options: &BTreeMap<String, std::path::PathBuf>,
    root: &std::path::Path,
) -> Result<String> {
    let mut h = Sha256::new();
    let mut add = |value: &[u8]| {
        h.update((value.len() as u64).to_le_bytes());
        h.update(value);
    };
    add(b"wros reviewed local cold start");
    add(xml.as_bytes());
    add(manifest.as_os_str().as_encoded_bytes());
    for name in ["--runtime", "--cosign"] {
        let file =
            verification::protected(options.get(name).ok_or("missing executable")?, root, false)?;
        add(file.as_os_str().as_encoded_bytes());
        add(sha256(std::fs::File::open(file).map_err(|e| e.to_string())?)?.as_bytes());
    }
    add(sha256(std::fs::File::open("/proc/self/exe").map_err(|e| e.to_string())?)?.as_bytes());
    for name in ["--cgroup-parent", "--policy-root", "--state-directory"] {
        let p = options.get(name).ok_or("missing deployment path")?;
        let real = p.canonicalize().map_err(|e| e.to_string())?;
        if !p.is_absolute() || &real != p {
            return Err("durable deployment paths must be canonical and absolute".into());
        }
        add(p.as_os_str().as_encoded_bytes());
    }
    for vm in &plan.processes {
        for name in std::iter::once(&vm.policy).chain(vm.vm_policy.iter()) {
            let p = verification::policy(&options["--policy-root"], name, root)?;
            add(p.as_os_str().as_encoded_bytes());
            add(sha256(std::fs::File::open(p).map_err(|e| e.to_string())?)?.as_bytes());
        }
    }
    Ok(format!("{:x}", h.finalize()))
}

fn approve(mut rights: BTreeMap<String, bool>) -> Result<BTreeMap<String, bool>> {
    if !io::stdin().is_terminal() {
        return Err("interactive review requires a terminal".into());
    }
    for (name, enabled) in &mut rights {
        loop {
            eprint!(
                "{name} [recommended {}] allow or deny? ",
                if *enabled { "allow" } else { "deny" }
            );
            io::stderr().flush().map_err(|e| e.to_string())?;
            let mut answer = String::new();
            if io::stdin()
                .read_line(&mut answer)
                .map_err(|e| e.to_string())?
                == 0
            {
                return Err("review cancelled".into());
            }
            match answer.trim() {
                "allow" => {
                    *enabled = true;
                    break;
                }
                "deny" => {
                    *enabled = false;
                    break;
                }
                _ => {}
            }
        }
    }
    loop {
        eprint!("additional edits [allow NAME | deny NAME | remove NAME | confirm]: ");
        io::stderr().flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?
            == 0
        {
            return Err("review cancelled".into());
        }
        match line.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["confirm"] => break,
            [action, name] if manifest::known_interface(name) => match *action {
                "allow" | "deny" => {
                    rights.insert(name.to_string(), *action == "allow");
                }
                "remove" => {
                    rights.remove(*name);
                }
                _ => eprintln!("unknown action"),
            },
            _ => eprintln!("enter a registered interface or confirm"),
        }
    }
    Ok(rights)
}
fn run() -> Result<()> {
    let usage = "usage: wros-deployer plan|review|verify|run|resume DEPLOYMENT.xml --policy-root DIRECTORY [--accept-recommendations for review/run] [--cosign EXECUTABLE --scratch-directory DIRECTORY for verify/run/resume] [--allow-unsigned ID=SHA256 | --allow-invalid-signature ID=SHA256 for verify/run] [--runtime EXECUTABLE --cgroup-parent DIRECTORY for run/resume] [--state-directory DIRECTORY for run, required for resume]";
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or(usage)?;
    if !matches!(
        action.as_str(),
        "plan" | "review" | "verify" | "run" | "resume"
    ) {
        return Err(usage.into());
    }
    let _signals = if matches!(action.as_str(), "run" | "resume") {
        Some(supervisor::Signals::install()?)
    } else {
        None
    };
    let manifest = std::path::PathBuf::from(args.next().ok_or(usage)?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let mut options = BTreeMap::new();
    let mut accept = false;
    let mut exceptions = BTreeMap::new();
    while let Some(key) = args.next() {
        if matches!(action.as_str(), "review" | "run")
            && key == "--accept-recommendations"
            && !accept
        {
            accept = true;
        } else if matches!(action.as_str(), "verify" | "run")
            && matches!(
                key.as_str(),
                "--allow-unsigned" | "--allow-invalid-signature"
            )
        {
            let value = args.next().ok_or(usage)?;
            let (id, digest) = value.split_once('=').ok_or(usage)?;
            let kind = if key == "--allow-unsigned" {
                Signature::Unsigned
            } else {
                Signature::Invalid
            };
            if exceptions
                .insert(id.to_owned(), (digest.to_owned(), kind))
                .is_some()
            {
                return Err("duplicate signature exception for one VM".into());
            }
        } else if key == "--policy-root"
            || matches!(action.as_str(), "verify" | "run" | "resume")
                && matches!(key.as_str(), "--cosign" | "--scratch-directory")
            || matches!(action.as_str(), "run" | "resume")
                && matches!(
                    key.as_str(),
                    "--runtime" | "--cgroup-parent" | "--state-directory"
                )
        {
            let value = args.next().ok_or(usage)?;
            if options
                .insert(key, std::path::PathBuf::from(value))
                .is_some()
            {
                return Err(usage.into());
            }
        } else {
            return Err(usage.into());
        }
    }
    let policies = options.get("--policy-root").ok_or(usage)?;
    let verifier = if matches!(action.as_str(), "verify" | "run" | "resume") {
        Some((
            options.get("--cosign").ok_or(usage)?,
            options.get("--scratch-directory").ok_or(usage)?,
        ))
    } else {
        None
    };
    let root = manifest.parent().ok_or("deployment directory missing")?;
    let bundle = std::fs::File::open(root).map_err(|e| e.to_string())?;
    let xml = read_xml(&manifest)?;
    let plan = deployment(&xml)?;
    let executing = matches!(action.as_str(), "run" | "resume");
    let execution = if executing {
        if !plan.drivers.is_empty() {
            return Err(
                "native provider execution is not yet qualified; run refuses driver declarations"
                    .into(),
            );
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err("run requires the privileged deployment supervisor".into());
        }
        Some((
            verification::protected(options.get("--runtime").ok_or(usage)?, root, false)?,
            options.get("--cgroup-parent").ok_or(usage)?,
        ))
    } else {
        None
    };
    let mut journal = options
        .get("--state-directory")
        .map(|p| state::Journal::open(p, root))
        .transpose()?;
    if action == "resume" && journal.is_none() {
        return Err("resume requires a durable state directory".into());
    }
    let approved_binding = if let Some(j) = &journal {
        let value = binding(&xml, &manifest, &plan, &options, root)?;
        if j.existing() || action == "resume" {
            j.check(&value)?;
        }
        Some(value)
    } else {
        None
    };
    if action == "resume" {
        let j = journal.as_ref().unwrap();
        for vm in &plan.processes {
            if let Some(kind) = j.entry(&vm.id)?.waiver {
                exceptions.insert(vm.id.clone(), (vm.digest.clone(), kind));
            }
        }
        println!("INFO Resuming only durable XML-authorized cold starts. The stored review is unchanged; no motion authority or running memory is restored.");
    }
    let mut approved = BTreeMap::new();
    let mut launches = Vec::new();
    for (id, (digest, _)) in &exceptions {
        if !plan
            .processes
            .iter()
            .any(|vm| &vm.id == id && &vm.digest == digest)
        {
            return Err(format!(
                "signature exception does not match a submitted VM and digest: {id:?}"
            ));
        }
    }
    if accept {
        eprintln!(
            "WARNING: accepting recommendations without individual review for this invocation"
        )
    }
    println!("deployment {:?}", plan.id);
    for driver in &plan.drivers {
        let path = local_file(&bundle, &driver.file)?;
        if sha256(path)? != driver.digest {
            return Err(format!("driver digest mismatch for {}", driver.id));
        }
        println!("INFO Local driver {:?}, vendor version {:?}, format {:?}, file {:?}, SHA256 {}, exclusive device {:?}, encrypted local attachment required.",
                 driver.id,driver.vendor_version,driver.kind,driver.file,driver.digest,driver.hardware_id);
    }
    for vm in plan.processes {
        let module = root.join(&vm.module);
        let file = local_file(&bundle, &vm.module)?;
        let policy = verification::policy(policies, &vm.policy, root)?;
        let mut rights = if action == "resume" {
            journal.as_ref().unwrap().entry(&vm.id)?.rights.clone()
        } else {
            match &vm.recommendations {
                Some(p) => recommendations(&manifest::xml_contents(local_file(&bundle, p)?)?)?,
                None => BTreeMap::new(),
            }
        };
        println!("INFO VM {:?}, module {:?}, SHA256 {}, signature policy {:?}, VM policy {:?}, memory limit {} bytes, task limit {}",vm.id,vm.module,vm.digest,vm.policy,vm.vm_policy,vm.memory_bytes,vm.pids);
        println!("INFO Recommendations {:?}, cold start at boot {}, authorized crash restart {}. Motion requires fresh safety confirmation and operator approval.",vm.recommendations,vm.boot_start,vm.crash_restart);
        println!("INFO Guest identity {:?}, CPU budget {} microseconds per 100000 microseconds, at most {} crash restarts, restart delay {} milliseconds. New network, IPC, UTS, mount and cgroup namespaces; private read-only /tmp image; no core files; at most 256 open descriptors.",vm.identity,vm.cpu_micros,vm.restart_limit,vm.restart_delay_ms);
        println!("INFO Allowed CPUs {}, memory nodes {}. Unspecified sets inherit the delegated parent; placement is not exclusive core reservation or a real-time guarantee. CPU quota can delay execution.",
                 vm.cpus.as_ref().map(ToString::to_string).unwrap_or_else(|| "inherited".into()),
                 vm.memory_nodes.as_ref().map(ToString::to_string).unwrap_or_else(|| "inherited".into()));
        let mut secondary_verification = true;
        let mut admitted = None;
        if let Some((exe, scratch)) = verifier {
            let admission = verification::admit(exe, scratch, root, file, &vm.digest, &policy);
            if executing && supervisor::stopping() {
                if let Some(j) = &mut journal {
                    if j.existing() {
                        j.stop(false)?;
                    }
                }
                return Err("operator stop cancelled verification".into());
            }
            let admission = admission?;
            let result = admission.signature;
            if executing {
                admitted = Some(verification::FrozenFile(supervisor::retained(
                    admission.module.0,
                )?));
            }
            if let Some((_, kind)) = exceptions.get(&vm.id) {
                eprintln!(
                    "WARNING: operator requested {:?} signature exception for VM {:?} at SHA256 {}",
                    kind, vm.id, vm.digest
                );
            }
            if result == Signature::Verified {
                println!(
                    "INFO WSEA policy and signature verified for VM {:?}, SHA256 {}",
                    vm.id, vm.digest
                );
            } else if exceptions
                .get(&vm.id)
                .is_some_and(|(_, kind)| *kind == result)
            {
                secondary_verification = false;
                eprintln!("WARNING: {:?} module admitted by explicit exception; VM verification disabled for {:?} at SHA256 {}", result, vm.id, vm.digest);
            } else {
                return Err(format!("{:?} signature rejected for {:?}", result, vm.id));
            }
        } else if sha256(file)? != vm.digest {
            return Err(format!("module digest mismatch for {}", vm.id));
        }
        if matches!(action.as_str(), "review" | "run") && !accept {
            rights = approve(rights)?
        }
        approved.insert(
            vm.id.clone(),
            state::Entry::reviewed(
                rights.clone(),
                exceptions.get(&vm.id).map(|(_, kind)| *kind),
            ),
        );
        let policy = if executing && secondary_verification {
            let secondary = verification::policy(
                policies,
                vm.vm_policy.as_ref().ok_or(
                    "signed run requires vm-policy with an independent VM-owned state directory",
                )?,
                root,
            )?;
            verification::equivalent_vm_policy(&policy, &secondary)?;
            println!("INFO VM secondary verification policy {:?}; identical trust rules with a separate VM-owned rollback store",secondary);
            secondary
        } else {
            policy
        };
        let module = if admitted.is_some() {
            std::path::PathBuf::from(supervisor::IMAGE_PATH)
        } else {
            module
        };
        let mut argv = vec![
            "--wasm-set-main-module-name".into(),
            vm.id.clone(),
            "--ros-scene-create".into(),
            vm.id.clone(),
            "--ros-scene-bind".into(),
            vm.id.clone(),
            vm.id.clone(),
        ];
        for (name, enabled) in rights {
            argv.extend([
                "--ros-scene-interface".into(),
                vm.id.clone(),
                name,
                if enabled { "allow" } else { "deny" }.into(),
            ]);
        }
        if verifier.is_none() {
            println!(
                "Admission preview argv {:?}",
                [
                    "wasm",
                    "secure",
                    "verify",
                    module.to_str().ok_or("non-UTF8 module")?,
                    "--policy",
                    policy.to_str().ok_or("non-UTF8 policy")?
                ]
            );
        }
        if secondary_verification {
            argv.extend([
                "--secure".into(),
                "module".into(),
                module.display().to_string(),
                policy.display().to_string(),
            ]);
        }
        argv.extend(["--run".into(), module.display().to_string()]);
        println!("VM argv {:?}", argv);
        if let Some(module) = admitted {
            launches.push(supervisor::Launch {
                process: vm,
                module,
                arguments: argv,
            });
        }
    }
    if let Some((runtime, parent)) = execution {
        if let Some(j) = &mut journal {
            if j.existing() {
                let ids = launches
                    .iter()
                    .map(|l| l.process.id.as_str())
                    .collect::<Vec<_>>();
                wros_deployer::cgroup::Hierarchy::reclaim(parent, &plan.id, &ids)?;
            }
            if supervisor::stopping() {
                if j.existing() {
                    j.stop(false)?;
                }
                return Err("operator stop cancelled admission".into());
            }
            let boot = state::boot_id()?;
            if action == "resume" {
                let active = j.resume(
                    boot,
                    &launches.iter().map(|l| &l.process).collect::<Vec<_>>(),
                )?;
                launches.retain(|l| active.contains(&l.process.id));
                let delay = launches
                    .iter()
                    .map(|l| l.process.restart_delay_ms)
                    .max()
                    .unwrap_or(0);
                println!(
                    "INFO Automatic cold-start delay {} milliseconds, no motion authority",
                    delay
                );
                let until =
                    std::time::Instant::now() + std::time::Duration::from_millis(u64::from(delay));
                while std::time::Instant::now() < until {
                    if supervisor::stopping() {
                        j.stop(false)?;
                        return Err("operator stop cancelled automatic restart".into());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            } else {
                j.approve(approved_binding.unwrap(), boot, approved)?;
            }
            if launches.is_empty() {
                println!(
                    "INFO No instance has an automatic cold-start grant for this state and boot."
                );
                return Ok(());
            }
        }
        println!("INFO Starting reviewed VM deployment with runtime {:?}, delegated cgroup {:?}. Boot registration is not performed by this command.",runtime,parent);
        supervisor::run_with_state(&runtime, parent, &plan.id, &launches, journal.as_mut())?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("wros-deployer: {e}");
        std::process::exit(1)
    }
}
