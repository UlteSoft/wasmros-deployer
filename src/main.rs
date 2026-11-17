//! Local preflight and operator review for one fixed bundle.
use wros_deployer::{manifest, verification, verdict::Signature};
use manifest::{Result, deployment,local_file,read_xml,recommendations,sha256};
use std::collections::BTreeMap;
use std::io::{self,IsTerminal,Write};

fn approve(mut rights:BTreeMap<String,bool>)->Result<BTreeMap<String,bool>>{
    if !io::stdin().is_terminal(){return Err("interactive review requires a terminal".into())}
    for (name,enabled) in &mut rights {
        loop{
            eprint!("{name} [recommended {}] allow or deny? ", if *enabled{"allow"}else{"deny"});
            io::stderr().flush().map_err(|e|e.to_string())?;
            let mut answer=String::new();if io::stdin().read_line(&mut answer).map_err(|e|e.to_string())?==0{return Err("review cancelled".into())}
            match answer.trim(){"allow"=>{*enabled=true;break},"deny"=>{*enabled=false;break},_=>{}}
        }
    }
    loop {
        eprint!("additional edits [allow NAME | deny NAME | remove NAME | confirm]: ");
        io::stderr().flush().map_err(|e|e.to_string())?;
        let mut line=String::new();
        if io::stdin().read_line(&mut line).map_err(|e|e.to_string())?==0{return Err("review cancelled".into())}
        match line.split_whitespace().collect::<Vec<_>>().as_slice(){
            ["confirm"]=>break,
            [action,name] if manifest::known_interface(name)=>match *action{
                "allow"|"deny"=>{rights.insert(name.to_string(),*action=="allow");},
                "remove"=>{rights.remove(*name);}, _=>eprintln!("unknown action")},
            _=>eprintln!("enter a registered interface or confirm")
        }
    }
    Ok(rights)
}
fn run()->Result<()> {
    let usage = "usage: wros-deployer plan|review|verify DEPLOYMENT.xml --policy-root DIRECTORY [--accept-recommendations for review] [--cosign EXECUTABLE --scratch-directory DIRECTORY for verify] [--allow-unsigned ID=SHA256 | --allow-invalid-signature ID=SHA256]";
    let mut args = std::env::args().skip(1);
    let action = args.next().ok_or(usage)?;
    if !matches!(action.as_str(), "plan" | "review" | "verify") { return Err(usage.into()); }
    let manifest = std::path::PathBuf::from(args.next().ok_or(usage)?)
        .canonicalize().map_err(|e| e.to_string())?;
    let mut options = BTreeMap::new();
    let mut accept = false;
    let mut exceptions = BTreeMap::new();
    while let Some(key) = args.next() {
        if action == "review" && key == "--accept-recommendations" && !accept {
            accept = true;
        } else if action == "verify" && matches!(key.as_str(), "--allow-unsigned" | "--allow-invalid-signature") {
            let value = args.next().ok_or(usage)?;
            let (id, digest) = value.split_once('=').ok_or(usage)?;
            let kind = if key == "--allow-unsigned" { Signature::Unsigned } else { Signature::Invalid };
            if exceptions.insert(id.to_owned(), (digest.to_owned(), kind)).is_some() {
                return Err("duplicate signature exception for one VM".into());
            }
        } else if key == "--policy-root" || action == "verify" && matches!(key.as_str(), "--cosign" | "--scratch-directory") {
            let value = args.next().ok_or(usage)?;
            if options.insert(key, std::path::PathBuf::from(value)).is_some() { return Err(usage.into()); }
        } else { return Err(usage.into()); }
    }
    let policies = options.get("--policy-root").ok_or(usage)?;
    let verifier = if action == "verify" {
        Some((options.get("--cosign").ok_or(usage)?, options.get("--scratch-directory").ok_or(usage)?))
    } else { None };
    let root=manifest.parent().ok_or("deployment directory missing")?;
    let bundle = std::fs::File::open(root).map_err(|e| e.to_string())?;
    let plan=deployment(&read_xml(&manifest)?)?;
    for (id, (digest, _)) in &exceptions {
        if !plan.processes.iter().any(|vm| &vm.id == id && &vm.digest == digest) {
            return Err(format!("signature exception does not match a submitted VM and digest: {id:?}"));
        }
    }
    if accept{eprintln!("WARNING: accepting recommendations without individual review for this invocation")}
    println!("deployment {:?}",plan.id);
    for driver in &plan.drivers {
        let path=local_file(&bundle,&driver.file)?;
        if sha256(path)?!=driver.digest{return Err(format!("driver digest mismatch for {}",driver.id))}
        println!("INFO Local driver {:?}, vendor version {:?}, format {:?}, file {:?}, SHA256 {}, exclusive device {:?}, encrypted local attachment required.",
                 driver.id,driver.vendor_version,driver.kind,driver.file,driver.digest,driver.hardware_id);
    }
    for vm in plan.processes{
        let module=root.join(&vm.module);
        let file=local_file(&bundle,&vm.module)?;let policy=verification::policy(policies,&vm.policy,root)?;
        let mut rights=match &vm.recommendations{Some(p)=>recommendations(&manifest::xml_contents(local_file(&bundle,p)?)?)?,None=>BTreeMap::new()};
        println!("INFO VM {:?}, module {:?}, SHA256 {}, signature policy {:?}, memory limit {} bytes, task limit {}",vm.id,vm.module,vm.digest,vm.policy,vm.memory_bytes,vm.pids);
        println!("INFO Recommendations {:?}, cold start at boot {}, authorized crash restart {}. Motion requires fresh safety confirmation and operator approval.",vm.recommendations,vm.boot_start,vm.crash_restart);
        let mut secondary_verification = true;
        if let Some((exe, scratch)) = verifier {
            let result = verification::verify(exe, scratch, root, file, &vm.digest, &policy)?;
            if let Some((_, kind)) = exceptions.get(&vm.id) {
                eprintln!("WARNING: operator requested {:?} signature exception for VM {:?} at SHA256 {}", kind, vm.id, vm.digest);
            }
            if result == Signature::Verified {
                println!("INFO WSEA policy and signature verified for VM {:?}, SHA256 {}", vm.id, vm.digest);
            } else if exceptions.get(&vm.id).is_some_and(|(_, kind)| *kind == result) {
                secondary_verification = false;
                eprintln!("WARNING: {:?} module admitted by explicit exception; VM verification disabled for {:?} at SHA256 {}", result, vm.id, vm.digest);
            } else {
                return Err(format!("{:?} signature rejected for {:?}", result, vm.id));
            }
        } else if sha256(file)? != vm.digest {
            return Err(format!("module digest mismatch for {}",vm.id));
        }
        if action=="review" && !accept {rights=approve(rights)?}
        let mut argv=vec!["--wasm-set-main-module-name".into(),vm.id.clone(),"--ros-scene-create".into(),vm.id.clone(),"--ros-scene-bind".into(),vm.id.clone(),vm.id.clone()];
        for (name,enabled) in rights{
            argv.extend(["--ros-scene-interface".into(),vm.id.clone(),name,if enabled{"allow"}else{"deny"}.into()]);
        }
        println!("verifier argv {:?}",["wasm","secure","verify",module.to_str().ok_or("non-UTF8 module")?,"--policy",policy.to_str().ok_or("non-UTF8 policy")?]);
        if secondary_verification {
            argv.extend(["--secure".into(),"module".into(),module.display().to_string(),policy.display().to_string()]);
        }
        argv.extend(["--run".into(),module.display().to_string()]);
        println!("VM argv {:?}",argv);
    } Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("wros-deployer: {e}");std::process::exit(1)}}
