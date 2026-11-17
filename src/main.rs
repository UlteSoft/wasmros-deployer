//! Local preflight and operator review for one fixed bundle.
use wros_deployer::manifest;
use manifest::{Result, deployment,local_file,read_xml,recommendations,sha256};
use std::collections::BTreeMap;
use std::io::{self,IsTerminal,Write};
use std::path::Path;

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
    let a=std::env::args().skip(1).collect::<Vec<_>>();
    if !(a.len()==2 || a.len()==3 && a[0]=="review" && a[2]=="--accept-recommendations") || !matches!(a[0].as_str(),"plan"|"review"){
        return Err("usage: wros-deployer plan DEPLOYMENT.xml | review DEPLOYMENT.xml [--accept-recommendations]".into())
    }
    let manifest=Path::new(&a[1]).canonicalize().map_err(|e|e.to_string())?;
    let root=manifest.parent().ok_or("deployment directory missing")?;
    let plan=deployment(&read_xml(&manifest)?)?;
    if a.len()==3{eprintln!("WARNING: accepting recommendations without individual review for this invocation")}
    println!("deployment {:?}",plan.id);
    for driver in &plan.drivers {
        let path=local_file(root,&driver.file)?;
        if sha256(&path)?!=driver.digest{return Err(format!("driver digest mismatch for {}",driver.id))}
        println!("INFO Local driver {:?}, vendor version {:?}, format {:?}, file {:?}, SHA256 {}, exclusive device {:?}, encrypted local attachment required.",
                 driver.id,driver.vendor_version,driver.kind,driver.file,driver.digest,driver.hardware_id);
    }
    for vm in plan.processes{
        let module=local_file(root,&vm.module)?;let policy=local_file(root,&vm.policy)?;
        if sha256(&module)?!=vm.digest{return Err(format!("module digest mismatch for {}",vm.id))}
        let mut rights=match &vm.recommendations{Some(p)=>recommendations(&read_xml(&local_file(root,p)?)?)?,None=>BTreeMap::new()};
        println!("INFO VM {:?}, module {:?}, SHA256 {}, signature policy {:?}, memory limit {} bytes, task limit {}",vm.id,vm.module,vm.digest,vm.policy,vm.memory_bytes,vm.pids);
        println!("INFO Recommendations {:?}, cold start at boot {}, authorized crash restart {}. Motion requires fresh safety confirmation and operator approval.",vm.recommendations,vm.boot_start,vm.crash_restart);
        if a[0]=="review"&&a.len()==2{rights=approve(rights)?}
        let mut argv=vec!["--wasm-set-main-module-name".into(),vm.id.clone(),"--ros-scene-create".into(),vm.id.clone(),"--ros-scene-bind".into(),vm.id.clone(),vm.id.clone()];
        for (name,enabled) in rights{
            argv.extend(["--ros-scene-interface".into(),vm.id.clone(),name,if enabled{"allow"}else{"deny"}.into()]);
        }
        println!("verifier argv {:?}",["wasm","secure","verify",module.to_str().ok_or("non-UTF8 module")?,"--policy",policy.to_str().ok_or("non-UTF8 policy")?]);
        argv.extend(["--secure".into(),"module".into(),module.display().to_string(),policy.display().to_string(),"--run".into(),module.display().to_string()]);
        println!("VM argv {:?}",argv);
    } Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("wros-deployer: {e}");std::process::exit(1)}}
