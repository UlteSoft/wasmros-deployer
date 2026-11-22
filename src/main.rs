//! Local preflight and operator review for one fixed bundle.
use manifest::{bundle::{Bundle, Kind}, deployment, local_file, recommendations, sha256, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use wros_deployer::{driver as native, guest_imports, manifest, service, state, supervisor, verdict::Signature, verification};

mod review;
mod wasm_library_admission;

/// Bind every automatic invocation to the exact reviewed configuration and
/// executable/trust-policy bytes. Recommendation files are not read on resume:
/// the independently reviewed permission map is stored in the protected record.
fn binding(
    deployment_digest: &str,
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
    add(b"wros reviewed local cold start with operator assessment v2");
    add(deployment_digest.as_bytes());
    add(manifest.as_os_str().as_encoded_bytes());
    for name in ["--runtime", "--cosign"] {
        let file =
            verification::protected(options.get(name).ok_or("missing executable")?, root, false)?;
        add(file.as_os_str().as_encoded_bytes());
        add(sha256(std::fs::File::open(file).map_err(|e| e.to_string())?)?.as_bytes());
    }
    add(sha256(std::fs::File::open("/proc/self/exe").map_err(|e| e.to_string())?)?.as_bytes());
    for name in ["--cgroup-parent", "--policy-root", "--state-directory"] {
        let Some(p) = options.get(name) else {
            if name == "--state-directory" {
                add(b"no durable approval");
                continue;
            }
            return Err("missing deployment path".into());
        };
        if name == "--cgroup-parent" && options.contains_key("--supervisor-cgroup") {
            // The independently managed service does not exist during initial
            // authorization. Bind its exact future name; resume opens and
            // validates the actual cgroup and current membership before spawn.
            service::root_path(p)?;
        } else {
            let real = p.canonicalize().map_err(|e| e.to_string())?;
            if !p.is_absolute() || &real != p {
                return Err("durable deployment paths must be canonical and absolute".into());
            }
        }
        add(p.as_os_str().as_encoded_bytes());
    }
    add(if options.contains_key("--supervisor-cgroup") {
        b"managed service"
    } else {
        b"external workload parent"
    });
    let mut library_trust = std::collections::BTreeSet::new();
    for vm in &plan.processes {
        for name in std::iter::once(&vm.policy).chain(vm.vm_policy.iter())
            .chain(vm.libraries.ordered.iter().flat_map(|lib| [&lib.policy, &lib.vm_policy])) {
            let p = verification::policy(&options["--policy-root"], name, root)?;
            if !vm.libraries.ordered.is_empty() {
                library_trust.insert(verification::policy_trust_root(&p, root)?);
            }
            add(p.as_os_str().as_encoded_bytes());
            add(sha256(std::fs::File::open(p).map_err(|e| e.to_string())?)?.as_bytes());
        }
    }
    for trust_root in library_trust {
        add(b"WSEA library graph trusted CA");
        add(trust_root.as_os_str().as_encoded_bytes());
        add(sha256(std::fs::File::open(trust_root).map_err(|e| e.to_string())?)?.as_bytes());
    }
    if !plan.drivers.is_empty() {
        let verifier = verification::protected(options.get("--elf-verifier").ok_or("missing ELF verifier")?, root, false)?;
        add(verifier.as_os_str().as_encoded_bytes());
        add(sha256(std::fs::File::open(verifier).map_err(|e| e.to_string())?)?.as_bytes());
        let driver_root = verification::protected(options.get("--driver-root").ok_or("missing driver root")?, root, true)?;
        add(driver_root.as_os_str().as_encoded_bytes());
        for driver in &plan.drivers {
            let name = driver.elf_signer.as_ref().ok_or("missing ELF signer policy")?;
            let signer = verification::policy(&options["--policy-root"], name, root)?;
            add(signer.as_os_str().as_encoded_bytes());
            add(sha256(std::fs::File::open(signer).map_err(|e| e.to_string())?)?.as_bytes());
        }
    }
    Ok(format!("{:x}", h.finalize()))
}

fn run() -> Result<()> {
    let usage = "usage: wros-deployer inspect-recovery MODULE.wasm\n       wros-deployer status --state-directory DIRECTORY\n       wros-deployer plan|review|verify|authorize|service|run|resume DEPLOYMENT.xml --policy-root DIRECTORY [--risk-report none|0..10 for plan/review/verify/authorize/run/resume] [--accept-recommendations-through-risk --risk-accept-threshold default|0..10 for review/authorize/run] [--cosign EXECUTABLE --scratch-directory DIRECTORY for verify/authorize/service/run/resume] [--allow-unsigned ITEM=SHA256 | --allow-invalid-signature ITEM=SHA256 for verify/authorize/run; ITEM is VM or VM/LIBRARY_NAMESPACE] [--elf-verifier EXECUTABLE for verify/run with drivers] [--allow-unsigned-elf ID=SHA256 | --allow-invalid-elf-signature ID=SHA256 for verify/run] [--driver-root DIRECTORY for run with drivers] [--runtime EXECUTABLE (--cgroup-parent DIRECTORY | --supervisor-cgroup DIRECTORY) for authorize/service/run/resume] [--state-directory DIRECTORY required for authorize/service/resume and managed run]";
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or(usage)?;
    if action == "status" {
        if args.next().as_deref() != Some("--state-directory") {
            return Err(usage.into());
        }
        let path = args.next().ok_or(usage)?;
        if args.next().is_some() {
            return Err(usage.into());
        }
        let status = state::status(std::path::Path::new(&path))?;
        let boot = if status.current_boot { "current" } else { "previous" };
        println!("INFO Recorded deployment state from the {boot} boot. Process liveness is unverified.");
        for instance in status.instances {
            println!(
                "INFO Recorded VM {:?} generation {}, phase {}, restarts {}",
                instance.id, instance.generation, instance.phase, instance.restarts
            );
        }
        return Ok(());
    }
    #[cfg(feature = "recovery-preflight")]
    if action == "inspect-recovery" {
        let module = args.next().ok_or(usage)?;
        if args.next().is_some() {
            return Err(usage.into());
        }
        let report = wros_deployer::recovery_module::inspect_file(std::path::Path::new(&module))
            .map_err(|e| e.to_string())?;
        println!("Recovery candidate SHA-256 {}", report.sha256);
        println!(
            "Entry {} function {}. Private memory {} to {} pages. Static instructions {}.",
            report.entry,
            report.function,
            report.initial_pages,
            report.maximum_pages,
            report.instructions
        );
        println!("Host imports 0. Read-only preflight. Deployment and recovery authority require separate approval.");
        return Ok(());
    }
    if !matches!(
        action.as_str(),
        "plan" | "review" | "verify" | "authorize" | "service" | "run" | "resume"
    ) {
        return Err(usage.into());
    }
    let _signals = if matches!(action.as_str(), "authorize" | "run" | "resume") {
        Some(supervisor::Signals::install()?)
    } else {
        None
    };
    let manifest = std::path::PathBuf::from(args.next().ok_or(usage)?)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let mut options = BTreeMap::new();
    let mut accept_through_risk = false;
    let mut accept_threshold = None;
    let mut risk_report = None;
    let mut exceptions = BTreeMap::new();
    let mut elf_exceptions = BTreeMap::new();
    while let Some(key) = args.next() {
        if manifest::native_preload_request(&key) {
            return Err(manifest::NATIVE_PRELOAD_REFUSED.into());
        } else if action != "service" && (key == "--risk-report" || key.starts_with("--risk-report=")) {
            if risk_report.is_some() {
                return Err("duplicate --risk-report option".into());
            }
            let value = match key.strip_prefix("--risk-report=") {
                Some(value) => value.into(),
                None => args.next().ok_or("missing --risk-report value")?,
            };
            risk_report = Some(review::RiskReport::parse(&value)?);
        } else if matches!(action.as_str(), "review" | "authorize" | "run")
            && key == "--accept-recommendations-through-risk"
        {
            if accept_through_risk {
                return Err("duplicate --accept-recommendations-through-risk".into());
            }
            accept_through_risk = true;
        } else if matches!(action.as_str(), "review" | "authorize" | "run")
            && (key == "--risk-accept-threshold" || key.starts_with("--risk-accept-threshold="))
        {
            if accept_threshold.is_some() {
                return Err("duplicate --risk-accept-threshold".into());
            }
            let value = match key.strip_prefix("--risk-accept-threshold=") {
                Some(value) => value.into(),
                None => args.next().ok_or("missing --risk-accept-threshold value")?,
            };
            accept_threshold = Some(review::acceptance_threshold(&value)?);
        } else if matches!(action.as_str(), "verify" | "authorize" | "run")
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
                return Err("duplicate signature exception for one Wasm image".into());
            }
        } else if matches!(action.as_str(), "verify" | "run")
            && matches!(key.as_str(), "--allow-unsigned-elf" | "--allow-invalid-elf-signature")
        {
            let value = args.next().ok_or(usage)?;
            let (id, digest) = value.split_once('=').ok_or(usage)?;
            let kind = if key == "--allow-unsigned-elf" {
                Signature::Unsigned
            } else {
                Signature::Invalid
            };
            if elf_exceptions
                .insert(id.to_owned(), (digest.to_owned(), kind))
                .is_some()
            {
                return Err("duplicate signature exception for one ELF driver".into());
            }
        } else if key == "--policy-root"
            || matches!(action.as_str(), "verify" | "run") && key == "--elf-verifier"
            || action == "run" && key == "--driver-root"
            || matches!(
                action.as_str(),
                "verify" | "authorize" | "service" | "run" | "resume"
            ) && matches!(key.as_str(), "--cosign" | "--scratch-directory")
            || matches!(action.as_str(), "authorize" | "service" | "run" | "resume")
                && matches!(
                    key.as_str(),
                    "--runtime" | "--cgroup-parent" | "--supervisor-cgroup" | "--state-directory"
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
    if accept_through_risk != accept_threshold.is_some() {
        return Err("use --accept-recommendations-through-risk together with --risk-accept-threshold default|0..10".into());
    }
    let risk_report = risk_report.unwrap_or_default();
    if let Some(root) = options.get("--supervisor-cgroup") {
        let parent = service::root_path(root)?.join("workloads");
        if options.insert("--cgroup-parent".into(), parent).is_some() {
            return Err("--supervisor-cgroup and --cgroup-parent are mutually exclusive".into());
        }
        if !options.contains_key("--state-directory") {
            return Err("managed execution requires durable approval".into());
        }
    }
    let policies = options.get("--policy-root").ok_or(usage)?;
    let verifier = if matches!(
        action.as_str(),
        "verify" | "authorize" | "service" | "run" | "resume"
    ) {
        Some((
            options.get("--cosign").ok_or(usage)?,
            options.get("--scratch-directory").ok_or(usage)?,
        ))
    } else {
        None
    };
    let root = manifest.parent().ok_or("deployment directory missing")?;
    let bundle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(root)
        .map_err(|e| e.to_string())?;
    let manifest_name = manifest.file_name().ok_or("deployment file name missing")?;
    let mut documents = Bundle::new(&bundle);
    let graph = documents.expand(std::path::Path::new(manifest_name), Kind::Deployment)?;
    let plan = deployment(&graph.xml)?;
    if action == "service" {
        print!(
            "{}",
            service::unit(
                &plan,
                &manifest,
                &std::env::current_exe().map_err(|e| e.to_string())?,
                &options
            )?
        );
        return Ok(());
    }
    let executing = matches!(action.as_str(), "run" | "resume");
    let authorizing = action == "authorize";
    let interactive = matches!(action.as_str(), "review" | "authorize" | "run");
    if interactive {
        review::require_terminal()?;
    }
    let manifest_digest = graph.digest;
    let execution = if executing || authorizing {
        if plan.supervisor.is_some() && !options.contains_key("--supervisor-cgroup") {
            return Err(
                "supervisor XML budgets require --supervisor-cgroup; refusing to ignore them"
                    .into(),
            );
        }
        if !plan.drivers.is_empty()
            && (action != "run" || options.contains_key("--state-directory")
                || plan.processes.iter().any(|vm| vm.boot_start || vm.crash_restart))
        {
            return Err("native provider execution requires an explicit run without automatic restart".into());
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
    if (action == "resume" || authorizing) && journal.is_none() {
        return Err("authorize/resume require a durable state directory".into());
    }
    let approved_binding = if executing || authorizing {
        let value = binding(&manifest_digest, &manifest, &plan, &options, root)?;
        if let Some(j) = &journal {
            if j.existing() || action == "resume" {
                j.check(&value)?;
            }
        }
        Some(value)
    } else {
        None
    };
    if let Some(path) = options.get("--supervisor-cgroup") {
        let limits = service::budget(&plan)?;
        let m = plan.supervisor.as_ref().unwrap();
        println!("INFO Independent supervisor root {:?}; manager memory {} bytes, tasks {}, CPU {} microseconds per 100000, CPUs {}, NUMA nodes {}; workload memory {} bytes, tasks {}; service cap {} bytes and {} tasks, including 4 MiB and 4 control tasks. These caps do not reserve hardware or guarantee real-time response.", path,
            m.memory_bytes, m.pids, m.cpu_micros, m.cpus.as_ref().map(ToString::to_string).unwrap_or_else(|| "inherited".into()),
            m.memory_nodes.as_ref().map(ToString::to_string).unwrap_or_else(|| "inherited".into()),
            limits.workload_memory, limits.workload_tasks, limits.memory, limits.tasks);
        if executing {
            service::prepare(path, &plan)?;
        } else if authorizing {
            wros_deployer::cgroup::require_inactive(path)?;
        }
    }
    if action == "resume" {
        let j = journal.as_ref().unwrap();
        for vm in &plan.processes {
            if let Some(kind) = j.entry(&vm.id)?.waiver {
                exceptions.insert(vm.id.clone(), (vm.digest.clone(), kind));
            }
            for (name, kind) in &j.entry(&vm.id)?.library_waivers {
                let lib = vm.libraries.ordered.iter().find(|lib| &lib.namespace == name)
                    .ok_or("durable library exception targets an absent module")?;
                exceptions.insert(format!("{}/{}", vm.id, name), (lib.digest.clone(), *kind));
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
            .any(|vm| (&vm.id == id && &vm.digest == digest)
                || vm.libraries.ordered.iter().any(|lib| id == &format!("{}/{}", vm.id, lib.namespace) && &lib.digest == digest))
        {
            return Err(format!(
                "signature exception does not match a submitted VM and digest or library and digest: {id:?}"
            ));
        }
    }
    if let Some(maximum) = accept_threshold {
        eprintln!("WARNING: adopting scored recommendations at or below {maximum}/10. Other recommendations require individual review. Initial deployment requires final confirmation.");
    }
    println!("deployment {:?}; manifest SHA256 {manifest_digest}", plan.id);
    println!("INFO Deployment configuration inputs {:?}", graph.inputs);
    review::show_deployment(&plan, risk_report);
    for (id, (digest, _)) in &elf_exceptions {
        if !plan
            .drivers
            .iter()
            .any(|driver| &driver.id == id && &driver.digest == digest)
        {
            return Err(format!(
                "ELF signature exception does not match a driver and digest: {id:?}"
            ));
        }
    }
    let mut native_launches = BTreeMap::new();
    for driver in &plan.drivers {
        if let Some((_, kind)) = elf_exceptions.get(&driver.id) {
            review::show_signature_exception(*kind, &driver.id, risk_report);
        }
        if executing {
            let elf = options.get("--elf-verifier").ok_or("run requires --elf-verifier for native drivers")?;
            let driver_root = options.get("--driver-root").ok_or("run requires --driver-root for native drivers")?;
            let attachment = driver.attachment.as_ref().ok_or("run needs an explicit driver attachment")?;
            let vm = attachment.vm.clone();
            println!("INFO Driver {:?} for VM {:?}, alias {:?}, sandbox {:?}, UID/GID {:?}, memory {} bytes, tasks {}, CPU {} per 100000, request deadline budget {}ms, private network and read-only filesystem, buffer.read.",
                     driver.id, vm, attachment.alias, attachment.sandbox, attachment.identity,
                     attachment.memory_bytes, attachment.pids, attachment.cpu_micros, attachment.request_millis);
            let exception = elf_exceptions.get(&driver.id).map(|(_, kind)| *kind);
            let admitted = verification::NativeAdmission::prepare(elf, root, &bundle, policies, driver, exception)
                .map_err(|error| format!("ELF driver {:?}: {error}", driver.id))?;
            println!("INFO Driver {:?} preflight {:?} for SHA256 {}", driver.id, admitted.verdict(), driver.digest);
            if admitted.verdict() != Signature::Verified {
                eprintln!("WARNING: {:?} ELF launch authorized by explicit exception for {:?} at SHA256 {}",
                          admitted.verdict(), driver.id, driver.digest);
            }
            native_launches.entry(vm).or_insert_with(Vec::new)
                .push(native::Launch::new(driver.clone(), admitted, driver_root, root)?);
            continue;
        } else if let Some((_, scratch)) = verifier {
            let elf = options
                .get("--elf-verifier")
                .ok_or("verify requires --elf-verifier for native drivers")?;
            let verdict = verification::verify_driver(elf, scratch, root, &bundle, policies, driver)
                .map_err(|error| format!("ELF driver {:?}: {error}", driver.id))?;
            if verdict == Signature::Verified {
                println!("INFO ELF CMS signature verified for driver {:?}", driver.id);
            } else if elf_exceptions
                .get(&driver.id)
                .is_some_and(|(_, kind)| *kind == verdict)
            {
                eprintln!("WARNING: {:?} ELF admitted for preflight by explicit exception for {:?} at SHA256 {}", verdict, driver.id, driver.digest);
            } else {
                return Err(format!(
                    "{:?} ELF signature rejected for {:?}",
                    verdict, driver.id
                ));
            }
        } else if sha256(local_file(&bundle, &driver.file)?)? != driver.digest {
            return Err(format!("driver digest mismatch for {}", driver.id));
        }
        println!("INFO Local driver {:?}, vendor version {:?}, format {:?}, file {:?}, SHA256 {}, exclusive device {:?}, encrypted local attachment required.",
                 driver.id,driver.vendor_version,driver.kind,driver.file,driver.digest,driver.hardware_id);
    }
    let mut prepared = Vec::with_capacity(plan.processes.len());
    for vm in &plan.processes {
        let module = root.join(&vm.module);
        let file = local_file(&bundle, &vm.module)?;
        let policy = verification::policy(policies, &vm.policy, root)?;
        let rights = if action == "resume" {
            journal.as_ref().unwrap().entry(&vm.id)?.rights.clone()
        } else {
            match &vm.recommendations {
                Some(p) => {
                    let policy_graph = documents.expand(p, Kind::Recommendations)?;
                    println!("INFO VM {:?} recommendation inputs {:?}, SHA256 {}", vm.id, policy_graph.inputs, policy_graph.digest);
                    recommendations(&policy_graph.xml)?
                }
                None => BTreeMap::new(),
            }
        };
        println!("INFO VM {:?}, module {:?}, SHA256 {}, signature policy {:?}, VM policy {:?}, memory limit {} bytes, task limit {}",vm.id,vm.module,vm.digest,vm.policy,vm.vm_policy,vm.memory_bytes,vm.pids);
        println!("INFO VM {:?} execution engine {:?}", vm.id, vm.engine);
        if let Some(policy) = vm.aot_policy {
            println!("INFO VM {:?} AOT compilation policy {:?}", vm.id, policy);
        }
        println!("INFO VM kernel device policy: null read/write; zero/random/urandom read only; other device opens and all mknod denied. This grants no guest imports or paths.");
        println!("INFO Recommendations {:?}, cold start at boot {}, authorized crash restart {}. Motion requires fresh safety confirmation and operator approval.",vm.recommendations,vm.boot_start,vm.crash_restart);
        println!("INFO Guest identity {:?}, CPU budget {} microseconds per 100000 microseconds, at most {} crash restarts, restart delay {} milliseconds. New network, IPC, UTS, mount and cgroup namespaces; private read-only /tmp image; no core files; at most 256 open descriptors.",vm.identity,vm.cpu_micros,vm.restart_limit,vm.restart_delay_ms);
        println!("INFO Allowed CPUs {}, memory nodes {}. Unspecified sets inherit the delegated parent; placement is not exclusive core reservation or a real-time guarantee. CPU quota can delay execution.",
                 vm.cpus.as_ref().map(ToString::to_string).unwrap_or_else(|| "inherited".into()),
                 vm.memory_nodes.as_ref().map(ToString::to_string).unwrap_or_else(|| "inherited".into()));
        let mut secondary_verification = true;
        let mut admitted = None;
        let main_image;
        if let Some((exe, scratch)) = verifier {
            let admission = verification::admit_image(exe, scratch, root, file, &vm.digest, &policy, vm.module_id.as_deref());
            if (executing || authorizing) && supervisor::stopping() {
                if let Some(j) = &mut journal {
                    if j.existing() {
                        j.stop(false)?;
                    }
                }
                return Err("operator stop cancelled verification".into());
            }
            let admission = admission?;
            let result = admission.signature;
            let imports = guest_imports::require_complete(guest_imports::inspect(&admission.module.0)?)?;
            review::show_imports(&vm.id, imports, &vm.libraries.requires, risk_report);
            main_image = admission.module;
            if let Some((_, kind)) = exceptions.get(&vm.id) {
                eprintln!(
                    "WARNING: operator requested {:?} signature exception for VM {:?} at SHA256 {}",
                    kind, vm.id, vm.digest
                );
                review::show_signature_exception(*kind, &vm.id, risk_report);
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
        } else {
            main_image = verification::snapshot_for_review(file, &vm.digest)?;
            let imports = guest_imports::inspect(&main_image.0)?;
            let imports = if interactive { guest_imports::require_complete(imports)? } else { imports };
            review::show_imports(&vm.id, imports, &vm.libraries.requires, risk_report);
        }
        let libraries = wasm_library_admission::prepare(vm, &main_image.0, &bundle, root, policies, verifier, executing,
            &exceptions, risk_report)?;
        if executing { admitted = Some(verification::FrozenFile(supervisor::retained(main_image.0)?)); }
        let policy = if (executing || authorizing || !vm.libraries.ordered.is_empty()) && secondary_verification {
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
        review::show_rights(if action == "resume" { "durable approval" } else { "recommendations" }, &vm.id, &rights, risk_report);
        prepared.push((vm, module, policy, rights, admitted, secondary_verification, libraries));
    }
    // No prompt may adopt an earlier VM before admission of its dependencies.
    for (vm, module, policy, mut rights, admitted, secondary_verification, libraries) in prepared {
        if interactive {
            rights = review::approve(&vm.id, rights, risk_report, accept_threshold)?;
            for driver in &plan.drivers {
                if let Some(a) = driver.attachment.as_ref().filter(|a| a.vm == vm.id) {
                    review::approve_payload(&driver.id, &vm.id, a.request_bytes, a.response_bytes, accept_threshold)?;
                }
            }
            review::show_rights("effective decisions", &vm.id, &rights, risk_report);
        }
        let drivers = native_launches.remove(&vm.id).unwrap_or_default();
        for provider in &drivers {
            let alias = &provider.artifact.attachment.as_ref().unwrap().alias;
            let allowed_imports = ["capability.open", "driver.connect", "driver.submit", "driver.result", "driver.disconnect"];
            if rights.get(&format!("driver/{alias}/buffer.read")) != Some(&true)
                || allowed_imports.iter().any(|name| rights.get(*name) != Some(&true))
                || manifest::reviewed_grants(&rights)?.contains_key(alias.as_str())
            {
                return Err(format!("VM {:?} requires separate reviewed driver permission and IPC imports for {alias:?}", vm.id));
            }
        }
        approved.insert(
            vm.id.clone(),
            if authorizing {
                state::Entry::for_service(
                    rights.clone(),
                    exceptions.get(&vm.id).map(|(_, kind)| *kind),
                )
            } else {
                state::Entry::reviewed(
                    rights.clone(),
                    exceptions.get(&vm.id).map(|(_, kind)| *kind),
                )
            },
        );
        approved.get_mut(&vm.id).unwrap().library_waivers = libraries.waivers;
        let module = if admitted.is_some() {
            std::path::PathBuf::from(supervisor::IMAGE_PATH)
        } else {
            module
        };
        let mut argv = vec![
            "--wasm-set-main-module-name".into(),
            vm.id.clone(),
            vm.engine.argument().into(),
            "--debug-permissions".into(),
            "none".into(),
            "--debug-dump-force".into(),
            "none".into(),
            "--runtime-memtag-mode".into(),
            "sync".into(),
            "--runtime-memtag-action".into(),
            "crash".into(),
            "--ros-scene-create".into(),
            vm.id.clone(),
            "--ros-scene-bind".into(),
            vm.id.clone(),
            vm.id.clone(),
        ];
        if let Some(policy) = vm.aot_policy {
            argv.extend(["--runtime-llvm-jit-policy".into(), policy.into()]);
        }
        if rights.is_empty() {
            println!("INFO VM {:?} has no reviewed interface or resource permissions.", vm.id);
        }
        for (alias, grant) in manifest::reviewed_grants(&rights)? {
            argv.extend(["--ros-scene-grant".into(), vm.id.clone(), alias.into(), grant.kind.into(),
                         grant.target.into(), grant.binding.into(), grant.operations.join(",")]);
        }
        // Plan the static routes even before the supervisor creates one-use channels.
        let routes = plan.drivers.iter().filter_map(|d| d.attachment.as_ref().map(|a| (d, a)))
            .filter(|(_, a)| a.vm == vm.id && rights.get(&format!("driver/{}/buffer.read", a.alias)) == Some(&true))
            .collect::<Vec<_>>();
        if !routes.is_empty() {
            argv.extend(["--ros-scene-driver-budget".into(), vm.id.clone(), routes.len().to_string(), vm.driver_budget_bytes.to_string()]);
            for (driver, route) in routes {
                argv.extend(["--ros-scene-grant".into(), vm.id.clone(), route.alias.clone(), "driver".into(),
                    driver.hardware_id.clone(), "registered-driver".into(), native::IMPORTS.join(",")]);
            }
        }
        let mut clock_policy = false;
        for (name, enabled) in rights {
            use manifest::Permission;
            let permission = Permission::from_key(&name).ok_or("unknown reviewed permission")?;
            if matches!(permission, Permission::ClockInterface(_) | Permission::ClockGrant(_)) && !clock_policy {
                argv.extend(["--wasip1-single-create".into(), vm.id.clone(),
                             "--wasip1-single-enable".into(), vm.id.clone()]);
                clock_policy = true;
            }
            let decision = if enabled { "allow" } else { "deny" };
            match permission {
                Permission::HideSelfReport | Permission::HideAbi => {
                    let interface = if permission == Permission::HideAbi { "abi" } else { manifest::SELF_REPORT };
                    println!("INFO VM {:?} ROSv2 interface {interface}: hidden", vm.id);
                    argv.extend(["--ros-scene-interface".into(), vm.id.clone(),
                                 interface.into(), "hidden".into()]);
                }
                Permission::RosInterface(name) => {
                    println!("INFO VM {:?} ROSv2 interface {}: {}", vm.id, name, decision);
                    argv.extend([
                        "--ros-scene-interface".into(), vm.id.clone(), name.into(), decision.into(),
                    ]);
                }
                Permission::LegacyRosAbi { host, interface } => {
                    println!("INFO VM {:?} deprecated legacy ABI version {interface}: {decision}; requires the separately compiled {host} module", vm.id);
                    for command in ["create", "enable", "interface"] {
                        argv.extend([format!("--{host}-single-{command}"), vm.id.clone()]);
                    }
                    argv.extend([interface.into(), decision.into()]);
                }
                Permission::ClockInterface(name) => {
                    println!("INFO VM {:?} WASIp1 clock interface {}: {}", vm.id, name, decision);
                    argv.extend(["--wasip1-single-interface".into(), vm.id.clone(), name.into(), decision.into()]);
                }
                Permission::ClockGrant(name) => {
                    println!("INFO VM {:?} WASIp1 clock read permission {}: {}", vm.id, name, decision);
                    let option = if enabled { "--wasip1-single-grant" } else { "--wasip1-single-deny" };
                    argv.extend([option.into(), vm.id.clone(), name.into()]);
                }
                Permission::Metadata { kind, alias, target, operation } => {
                    println!("INFO VM {:?} metadata grant {:?}, {} {:?}, operation {}: {}", vm.id, alias, kind, target, operation, decision);
                }
                Permission::SelfReport(selector) => {
                    println!("INFO VM {:?} report selector {:?}: {}", vm.id, selector,
                        if enabled { "no reduction for this selector" } else { "deny" });
                    if !enabled {
                        argv.extend(["--ros-scene".into(), vm.id.clone(), "permission.report".into(), selector.into(), "deny".into()]);
                    }
                }
                Permission::LocalOperation { kind, alias, operation } => {
                    println!("INFO VM {:?} local {} resource {:?} operation {}: {}", vm.id, kind, alias, operation, decision);
                }
                Permission::DriverRead(alias) => {
                    println!("INFO VM {:?} native driver {:?} buffer.read: {}", vm.id, alias, decision);
                }
            }
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
                if vm.module_id.is_some() { "named-module" } else { "module" }.into(),
                module.display().to_string(),
                policy.display().to_string(),
            ]);
            if let Some(id) = &vm.module_id { argv.push(id.clone()); }
        }
        argv.extend(libraries.argv);
        argv.extend(["--run".into(), module.display().to_string()]);
        println!("VM argv {:?}", argv);
        if let Some(module) = admitted {
            launches.push(supervisor::Launch {
                process: vm.clone(),
                module,
                libraries: libraries.images,
                arguments: argv,
                drivers,
            });
        }
    }
    if let Some((runtime, parent)) = execution {
        if interactive {
            review::confirm_deployment(&action, &plan.id, &manifest_digest)?;
        }
        if supervisor::stopping() {
            if let Some(j) = journal.as_mut().filter(|j| j.existing()) {
                j.stop(false)?;
            }
            return Err("operator stop cancelled deployment before authorization".into());
        }
        documents.revalidate()?;
        let current_binding = binding(&manifest_digest, &manifest, &plan, &options, root)
            .map_err(|error| format!("could not revalidate the reviewed deployment before launch: {error}"))?;
        if Some(current_binding) != approved_binding {
            return Err("reviewed executable, trust policy or deployment path changed before launch".into());
        }
        if authorizing {
            if !options.contains_key("--supervisor-cgroup") {
                wros_deployer::cgroup::require_inactive(parent)?;
            }
            if supervisor::stopping() {
                if let Some(j) = journal.as_mut().filter(|j| j.existing()) {
                    j.stop(false)?;
                }
                return Err("operator stop cancelled authorization".into());
            }
            journal.as_mut().unwrap().approve(
                approved_binding.unwrap(),
                state::boot_id()?,
                approved,
            )?;
            println!("INFO Reviewed authority saved. No process was started. The independent supervisor may now invoke resume; changed configuration requires fresh review.");
            return Ok(());
        }
        // Exclude every competing manager before reclaim can signal a prior
        // tree or resume can consume its approval. Keep the full reviewed set
        // reserved even when only a subset has an automatic cold-start grant.
        let identities = supervisor::reserve(parent, &plan.id, &launches)?;
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
        supervisor::run_reserved(
            &runtime,
            parent,
            &plan.id,
            &launches,
            journal.as_mut(),
            &identities,
        )?;
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("wros-deployer: {e}");
        std::process::exit(1)
    }
}
