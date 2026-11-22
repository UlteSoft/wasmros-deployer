//! Native read-only provider launch with a dedicated filesystem and bootstrap.
use crate::attachment::{self, Binding, Credentials, Endpoint, Limits, Peer};
use crate::manifest::{DriverArtifact, Result};
use crate::supervisor::{retained, spawn_pinned};
use crate::verification::{self, NativeAdmission};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct Launch {
    pub artifact: DriverArtifact,
    pub admission: NativeAdmission,
    sandbox: PathBuf,
}
impl Launch {
    pub fn new(artifact: DriverArtifact, admission: NativeAdmission, root: &Path, bundle: &Path) -> Result<Self> {
        let attachment = artifact.attachment.as_ref().ok_or("run needs an explicit driver attachment")?;
        let root = verification::protected(root, bundle, true)?;
        if root == Path::new("/") || bundle.starts_with(&root) {
            return Err("driver sandbox root must be independent of the submitted bundle".into());
        }
        let sandbox = verification::protected(&root.join(&attachment.sandbox), bundle, true)?;
        crate::workload_fs::immutable_tree(&sandbox, 16384)?;
        let proc = verification::protected(&sandbox.join("proc"), bundle, true)?;
        if fs::read_dir(proc).map_err(|e| e.to_string())?.next().is_some() {
            return Err("driver sandbox needs an empty proc mountpoint".into());
        }
        Ok(Self { artifact, admission, sandbox })
    }
}

/// A one-use bootstrap, retained only in the trusted supervisor.
pub(crate) struct Bootstrap {
    provider: Peer,
    server: Endpoint,
    client: Endpoint,
    courier: File,
    binding: Binding,
    limits: Limits,
}

pub(crate) const IMPORTS: [&str; 4] = [
    "driver.connect", "driver.submit", "driver.result", "driver.disconnect",
];

fn hex(value: &[u8]) -> String {
    value.iter().map(|n| format!("{n:02x}")).collect()
}
impl Bootstrap {
    pub(crate) fn vm_arguments(&self, launch: &Launch, vm: &str) -> (Vec<String>, [i32; 3]) {
        let config = launch.artifact.attachment.as_ref().unwrap();
        let alias = config.alias.as_str();
        let peer = self.provider.credentials();
        let inherited = [
            self.client.channel().as_raw_fd(),
            self.client.identity().as_raw_fd(),
            self.provider.clock().as_raw_fd(),
        ];
        let mut args = [
            "--ros-scene-grant", vm, alias, "driver", &launch.artifact.hardware_id,
            "registered-driver", &IMPORTS.join(","),
            "--ros-scene-driver-budget", vm, "1", "1048576",
            "--ros-scene-driver-channel", vm, alias, vm,
        ].into_iter().map(str::to_owned).collect::<Vec<_>>();
        args.extend([
            inherited[0].to_string(), peer.pid.to_string(), peer.uid.to_string(), peer.gid.to_string(),
            hex(&self.binding.deployment), hex(&self.binding.vm), hex(&self.binding.scope),
            hex(&self.binding.provider), hex(&self.binding.session), hex(&self.binding.contract),
            self.limits.request_bytes.to_string(), self.limits.response_bytes.to_string(),
            self.limits.request_ns.to_string(), self.limits.session_until_ns.to_string(),
            inherited[1].to_string(), inherited[2].to_string(),
        ]);
        args.extend(["--ros-scene-driver-schema", vm, alias, "buffer.read", "64", "64", "8"]
            .into_iter().map(str::to_owned));
        (args, inherited)
    }

    pub(crate) fn deliver(self, child: &Child, identity: (u32, u32)) -> Result<()> {
        let vm = Peer::pin(Credentials { pid: child.id(), uid: identity.0, gid: identity.1 })?;
        let record = self.server.bootstrap(self.binding, self.limits, &self.provider, &vm)?;
        attachment::deliver(&self.courier, self.server, record, &self.provider, &vm, Duration::from_secs(2))
    }
}

pub(crate) fn start(launch: &Launch, enrollment: File) -> Result<((Child, File), Bootstrap)> {
    let config = launch.artifact.attachment.as_ref().ok_or("missing driver attachment")?;
    let [courier, delivery] = attachment::carrier()?;
    let [client, server] = attachment::endpoints()?;
    let binding = Binding::fresh(
        attachment::identifier()?, attachment::identifier()?, attachment::identifier()?,
        attachment::identifier()?, config.socket_contract,
    )?;
    let limits = Limits {
        request_bytes: config.request_bytes.into(), response_bytes: config.response_bytes.into(), request_ns: u64::from(config.request_millis) * 1_000_000,
        session_until_ns: attachment::monotonic_ns()?.checked_add(3_600_000_000_000)
            .ok_or("attachment deadline overflow")?,
    };
    let enrollment = retained(enrollment)?;
    let delivery = retained(delivery)?;
    let fd = delivery.as_raw_fd();
    let image = launch.admission.image.0.as_raw_fd();
    let identity = config.identity;
    let parent = unsafe { libc::getpid() };
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let sandbox = CString::new(launch.sandbox.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let proc_target = CString::new(launch.sandbox.join("proc").as_os_str().as_bytes())
        .map_err(|e| e.to_string())?;
    let args = [launch.artifact.id.clone(), fd.to_string(), parent.to_string(),
                uid.to_string(), gid.to_string(), "read-only".into()]
        .into_iter().map(CString::new).collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut command = Command::new("/");
    command.env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            let fail = std::io::Error::last_os_error;
            if libc::write(enrollment.as_raw_fd(), b"0".as_ptr().cast(), 1) != 1 {
                return Err(fail());
            }
            // The nonrecursive private bind excludes submounts of the curated root.
            if libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS |
                libc::CLONE_NEWCGROUP | libc::CLONE_NEWNS) != 0
                || libc::mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(),
                               libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0
                || libc::mount(sandbox.as_ptr(), sandbox.as_ptr(), std::ptr::null(),
                               libc::MS_BIND, std::ptr::null()) != 0
                || libc::mount(std::ptr::null(), sandbox.as_ptr(), std::ptr::null(),
                               libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY |
                               libc::MS_NOSUID | libc::MS_NODEV, std::ptr::null()) != 0
                // Preserve PID credentials for IPC with the VM. Only the
                // dedicated UID's process entries are visible in this procfs.
                || libc::mount(c"proc".as_ptr(), proc_target.as_ptr(), c"proc".as_ptr(),
                               libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                               c"hidepid=2,subset=pid".as_ptr().cast()) != 0
                || libc::chroot(sandbox.as_ptr()) != 0
                || libc::chdir(c"/".as_ptr()) != 0
            {
                return Err(fail());
            }
            crate::supervisor::finish_child(identity, parent, crate::containment::Role::NativeDriver)?;
            if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                return Err(fail());
            }
            let argv = [args[0].as_ptr(), args[1].as_ptr(), args[2].as_ptr(), args[3].as_ptr(),
                        args[4].as_ptr(), args[5].as_ptr(), std::ptr::null()];
            let envp = [std::ptr::null::<libc::c_char>()];
            libc::syscall(libc::SYS_execveat, image, c"".as_ptr(), argv.as_ptr(),
                          envp.as_ptr(), libc::AT_EMPTY_PATH);
            Err(fail())
        });
    }
    // Verification runs after preparing resources and before starting any provider code.
    launch.admission.reverify().map_err(|error| format!("driver {:?} launch verification refused before exec: {error}", launch.artifact.id))?;
    if crate::supervisor::stopping() {
        return Err("operator stop cancelled driver launch".into());
    }
    let (mut child, pidfd) = spawn_pinned(command, "native driver")?;
    let provider = match Peer::pin(Credentials { pid: child.id(), uid: identity.0, gid: identity.1 }) {
        Ok(peer) => peer,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    Ok(((child, pidfd), Bootstrap { provider, server, client, courier, binding, limits }))
}
