//! Test-only orchestration of the production provisioning primitives.
//! The deployer CLI does not acquire native-provider launch authority from this
//! harness. Privileged UID/cgroup tests run only in the disposable QEMU guest.
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::FileExt, process::CommandExt};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use wros_deployer::attachment as a;
struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|n| format!("{n:02x}")).collect()
}
fn prepare(command: &mut Command, inherited: Vec<i32>, uid: u32, group: &str, network: Option<File>) {
    let privileged = unsafe { libc::geteuid() == 0 };
    let parent = unsafe { libc::getpid() };
    let enrollment = std::env::var("WROS_TEST_CHILD_CGROUP_ROOT")
        .ok()
        .map(|root| {
            assert!(privileged);
            let path = std::path::Path::new(&root).join(group);
            // Test-deployer authority only. Install before enrollment; closing
            // this handle leaves the kernel filter active until group removal.
            let directory = File::open(&path).unwrap();
            let _devices = wros_deployer::devices::Policy::vm()
                .attach_empty(&directory)
                .unwrap();
            println!("TEST_DEVICE_FILTER_INSTALLED {group}");
            let file = OpenOptions::new()
                .write(true)
                .open(path.join("cgroup.procs"))
                .unwrap();
            wros_deployer::supervisor::retained(file).unwrap()
        });
    command.stdin(Stdio::null()).env_clear();
    unsafe {
        command.pre_exec(move || {
            let fail = || std::io::Error::last_os_error();
            if let Some(file) = &enrollment {
                if libc::write(file.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                    return Err(fail());
                }
            }
            if privileged {
                let ipc_and_uts = libc::CLONE_NEWIPC | libc::CLONE_NEWUTS;
                if let Some(network) = &network {
                    if libc::setns(network.as_raw_fd(), libc::CLONE_NEWNET) != 0
                        || libc::unshare(ipc_and_uts) != 0
                    {
                        return Err(fail());
                    }
                } else if libc::unshare(ipc_and_uts | libc::CLONE_NEWNET) != 0 {
                    return Err(fail());
                }
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(uid, uid, uid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(fail());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent
            {
                return Err(fail());
            }
            if privileged && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(fail());
            }
            wros_deployer::containment::pin_namespaces()?;
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(fail());
            }
            for fd in &inherited {
                if libc::fcntl(*fd, libc::F_SETFD, 0) != 0 {
                    return Err(fail());
                }
            }
            Ok(())
        });
    }
}

/// Run the synthetic DDS telemetry writer in the provider's loopback-only
/// namespace. The writer has an independent UID and resource limits.
fn start_unitree_writer(program: &str, provider_pid: u32) -> Child {
    let path = format!("/proc/{provider_pid}/ns/net");
    let network = File::open(&path).unwrap();
    let setup = Command::new("/bin/busybox")
        .args(["nsenter", &format!("--net={path}"), "/bin/busybox",
            "ip", "link", "set", "lo", "multicast", "on", "up"])
        .status()
        .unwrap();
    assert!(setup.success(), "bring up the private DDS loopback");

    let mut writer = Command::new(program);
    writer.arg("publish");
    prepare(&mut writer, vec![], 24003, "writer", Some(network));
    let child = writer.spawn().unwrap();
    let root = std::env::var_os("WROS_TEST_CHILD_CGROUP_ROOT").unwrap();
    let group = std::path::Path::new(&root).join("writer/cgroup.procs");
    assert!(std::fs::read_to_string(group).unwrap().lines()
        .any(|pid| pid == child.id().to_string()));
    child
}

fn corrupt(file: File, offset: usize) -> File {
    let mut record = [0u8; 256];
    file.read_exact_at(&mut record, 0).unwrap();
    record[offset] ^= 0x80;
    let fd = unsafe {
        libc::memfd_create(
            c"test-corrupted-bootstrap".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0);
    let output = unsafe { File::from_raw_fd(fd) };
    output.write_all_at(&record, 0).unwrap();
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, a::SEALS) }, 0);
    output
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(matches!(args.len(), 5 | 7), "runtime peer module mode [engine WSEA-policy]");
    let mode = &args[4];
    assert!([
        "success",
        "wrong-key",
        "wrong-binding",
        "wrong-descriptor",
        "bad-profile",
        "bad-ready",
        "peer-exit",
        "unexpected-rights",
        "bad-origin"
    ]
    .contains(&mode.as_str()));
    let unitree = args.len() == 7;
    let root = unsafe { libc::geteuid() == 0 };
    if unitree {
        assert!(root && std::env::var_os("WROS_TEST_CHILD_CGROUP_ROOT").is_some());
        assert!(matches!(args[5].as_str(), "--runtime-int" | "--runtime-aot"));
        assert!(matches!(mode.as_str(), "success" | "wrong-key"));
    }
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let vm_uid = if root { 24001 } else { uid };
    let provider_uid = if root { 24002 } else { uid };
    let vm_gid = if root { 24001 } else { gid };
    let provider_gid = if root { 24002 } else { gid };
    let [client, server] = a::endpoints().unwrap();
    let [wrong_client, _wrong_server] = a::endpoints().unwrap();
    let [sender, receiver] = a::carrier().unwrap();
    let mut peer = Command::new(&args[2]);
    peer.args([
        receiver.as_raw_fd().to_string(),
        std::process::id().to_string(),
        uid.to_string(),
        gid.to_string(),
        mode.to_string(),
    ]);
    prepare(
        &mut peer,
        vec![receiver.as_raw_fd()],
        provider_uid,
        "provider",
        None,
    );
    let mut children = Children(vec![peer.spawn().unwrap()]);
    drop(receiver);
    let provider = a::Peer::pin(a::Credentials {
        pid: children.0[0].id(),
        uid: provider_uid,
        gid: provider_gid,
    })
    .unwrap();
    let contract = if unitree {
        Sha256::digest(include_bytes!("unitree_low_state_contract.txt")).into()
    } else {
        std::array::from_fn(|i| (i + 1) as u8)
    };
    let binding = a::Binding::fresh(
        a::identifier().unwrap(),
        a::identifier().unwrap(),
        a::identifier().unwrap(),
        a::identifier().unwrap(),
        contract,
    )
    .unwrap();
    let limits = a::Limits {
        request_bytes: 32,
        response_bytes: 32,
        request_ns: 180_000_000_000,
        session_until_ns: a::monotonic_ns().unwrap() + 180_000_000_000,
    };
    let key = if mode == "wrong-key" {
        wrong_client.identity()
    } else {
        client.identity()
    };
    let mut command = Command::new(&args[1]);
    command.args([
        "--wasm-set-main-module-name",
        "main",
        if unitree { &args[5] } else { "--runtime-int" },
        "--ros-scene-create",
        "robot",
        "--ros-scene-bind",
        "robot",
        "main",
    ]);
    let ordinary_names = [
        "driver.connect",
        "driver.submit",
        "driver.result",
        "driver.describe",
        "driver.disconnect",
    ];
    let telemetry_names = ["driver.connect", "driver.submit", "driver.result", "driver.disconnect"];
    let names = if unitree { &telemetry_names[..] } else { &ordinary_names[..] };
    let (alias, resource, schema) = if unitree {
        ("go2-state", "go2-low-state", "buffer.read")
    } else {
        ("arm-query", "arm-parameters", "parameter.exists")
    };
    for name in std::iter::once("capability.open").chain(names.iter().copied()) {
        command.args(["--ros-scene-interface", "robot", name, "allow"]);
    }
    command.args([
        "--ros-scene-grant",
        "robot",
        alias,
        "driver",
        resource,
        "registered-driver",
        &names.join(","),
        "--ros-scene-driver-budget",
        "robot",
        "1",
        "1048576",
    ]);
    command.args(["--ros-scene-driver-channel", "robot", alias, "main"]);
    command.args([
        client.channel().as_raw_fd().to_string(),
        provider.credentials().pid.to_string(),
        provider_uid.to_string(),
        provider_gid.to_string(),
        hex(&binding.deployment),
        hex(&binding.vm),
        hex(&binding.scope),
        hex(&binding.provider),
        hex(&binding.session),
        hex(&binding.contract),
        limits.request_bytes.to_string(),
        limits.response_bytes.to_string(),
        limits.request_ns.to_string(),
        limits.session_until_ns.to_string(),
        key.as_raw_fd().to_string(),
        provider.clock().as_raw_fd().to_string(),
    ]);
    command.args([
        "--ros-scene-driver-schema",
        "robot",
        alias,
        schema,
        "64",
        "64",
        "8",
    ]);
    if unitree {
        for operation in ["clock.create", "clock.read"] {
            command.args(["--ros-scene-interface", "robot", operation, "allow"]);
        }
        command.args([
            "--ros-scene-grant", "robot", "steady", "clock.steady", "steady", "local",
            "clock.create,clock.read",
            "--runtime-compile-threads", "0",
            "--runtime-llvm-jit-cache-path", "disable",
            "--runtime-memtag-mode", "sync",
            "--debug-fault-action", "exit",
            "--secure", "module", &args[3], &args[6],
        ]);
    }
    command.args(["--run", &args[3]]);
    prepare(
        &mut command,
        vec![
            client.channel().as_raw_fd(),
            key.as_raw_fd(),
            provider.clock().as_raw_fd(),
        ],
        vm_uid,
        "vm",
        None,
    );
    children.0.push(command.spawn().unwrap());
    let vm = a::Peer::pin(a::Credentials {
        pid: children.0[1].id(),
        uid: vm_uid,
        gid: vm_gid,
    })
    .unwrap();
    if let Ok(root) = std::env::var("WROS_TEST_CHILD_CGROUP_ROOT") {
        for (name, pid) in [
            ("vm", vm.credentials().pid),
            ("provider", provider.credentials().pid),
        ] {
            let file = std::path::Path::new(&root).join(name).join("cgroup.procs");
            assert!(std::fs::read_to_string(file)
                .unwrap()
                .lines()
                .any(|line| line == pid.to_string()));
        }
        let left = std::fs::metadata(format!("/proc/{}/ns/net", vm.credentials().pid)).unwrap();
        let right =
            std::fs::metadata(format!("/proc/{}/ns/net", provider.credentials().pid)).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_ne!((left.dev(), left.ino()), (right.dev(), right.ino()));
    }
    let mut bound = binding;
    if mode == "wrong-binding" {
        bound.session = a::identifier().unwrap();
    }
    let mut record = server.bootstrap(bound, limits, &provider, &vm).unwrap();
    if mode == "bad-profile" {
        record = corrupt(record, 24);
    }
    if mode == "wrong-descriptor" {
        record = corrupt(record, 232);
    }
    if mode == "peer-exit" {
        children.0[0].kill().unwrap();
        children.0[0].wait().unwrap();
    }
    let descriptors_before = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let delivery = a::deliver(
        &sender,
        server,
        record,
        &provider,
        &vm,
        Duration::from_secs(2),
    );
    assert_eq!(
        std::fs::read_dir("/proc/self/fd").unwrap().count() + 3,
        descriptors_before,
        "delivered or rejected descriptors are closed"
    );
    if ["bad-ready", "peer-exit", "unexpected-rights", "bad-origin"].contains(&mode.as_str()) {
        assert!(delivery.is_err());
    } else {
        delivery.unwrap();
    }
    drop(sender);
    drop(client);
    drop(wrong_client);
    let writer = if unitree && mode == "success" {
        Some(start_unitree_writer(&args[2], provider.credentials().pid))
    } else {
        None
    };
    let _writer = Children(writer.into_iter().collect());
    let until = Instant::now() + Duration::from_secs(15);
    let mut statuses = [None, None];
    while Instant::now() < until {
        for (i, child) in children.0.iter_mut().enumerate() {
            if statuses[i].is_none() {
                statuses[i] = child.try_wait().unwrap();
            }
        }
        if statuses.iter().all(Option::is_some) {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        statuses.iter().all(Option::is_some),
        "bounded child completion"
    );
    if mode == "success" {
        assert!(
            statuses.iter().all(|x| x.unwrap().success()),
            "{statuses:?}"
        );
    } else {
        assert!(
            !statuses[1].unwrap().success(),
            "VM must refuse corrupted provisioning"
        );
        assert!(!statuses[0].unwrap().success());
    }
    if !unitree {
        println!("CASE rust-provisioned-{mode} PASS");
    }
}
