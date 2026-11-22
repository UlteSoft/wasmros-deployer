//! Bounded local VM supervisor. It receives fully admitted images and reviewed
//! argument vectors. Enrollment, namespace creation, identity drop and immutable
//! descriptor inheritance complete before the first VM instruction executes.
//! Attached native providers share the deployment shutdown boundary while using
//! a separate cgroup, host identity and filesystem.
use crate::{
    audit::Events,
    cgroup::{Hierarchy, Workload},
    manifest::{Process, Result},
    recovery::Instance,
    verification::FrozenFile,
};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOP: AtomicBool = AtomicBool::new(false);
static SIGNALS: AtomicBool = AtomicBool::new(false);
const STOP_GRACE: Duration = Duration::from_secs(2);
const STOP_SETTLE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const DRIVER_CLOSE_GRACE: Duration = Duration::from_millis(250);
/// A private read-only copy of the sealed image. VM's normal no-follow loader
/// accepts this regular path without weakening its symlink rejection policy.
pub const IMAGE_PATH: &str = "/tmp/wros-admitted.wasm";
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}
pub struct Signals {
    saved: Vec<(i32, libc::sigaction)>,
    owns: bool,
}
impl Signals {
    pub fn install() -> Result<Self> {
        if SIGNALS.swap(true, Ordering::SeqCst) {
            return Ok(Self {
                saved: Vec::new(),
                owns: false,
            });
        }
        STOP.store(false, Ordering::SeqCst);
        let mut saved = Self {
            saved: Vec::new(),
            owns: true,
        };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = stop as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            saved.saved.push((signal, old));
        }
        Ok(saved)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, old) in &self.saved {
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
        if self.owns {
            SIGNALS.store(false, Ordering::SeqCst);
        }
    }
}
pub fn stopping() -> bool {
    STOP.load(Ordering::SeqCst)
}

pub struct Launch {
    pub process: Process,
    pub module: FrozenFile,
    pub libraries: Vec<FrozenFile>,
    pub arguments: Vec<String>,
    pub drivers: Vec<crate::driver::Launch>,
}
struct RunningDriver {
    child: Option<Child>,
    pidfd: Option<File>,
    ended: Option<Instant>,
    output: DiagnosticBudget,
}
struct Running {
    child: Option<Child>,
    pidfd: Option<File>,
    state: Instance,
    generation: u64,
    restarts: u32,
    next: Option<Instant>,
    failed: bool,
    output: DiagnosticBudget,
    started: bool,
    drivers: Vec<RunningDriver>,
}
struct Session<'a> {
    hierarchy: Hierarchy,
    launches: &'a [Launch],
    slots: Vec<Running>,
    events: &'a Events,
    journal: Option<&'a mut crate::state::Journal>,
    driver_groups: Vec<std::ops::Range<usize>>,
    roots: Vec<std::sync::Arc<crate::workload_fs::Root>>,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        let _ = self.force_stop();
    }
}
fn signal(pidfd: &File, number: i32) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            number,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}

fn finish_driver(
    driver: &mut RunningDriver,
    id: &str,
    generation: u64,
    events: &Events,
    deadline: Instant,
) -> Result<()> {
    while let Some(child) = &mut driver.child {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            output(child, "Driver", id, generation, &mut driver.output, events);
            driver.child = None;
            driver.pidfd = None;
            events.send(format!("INFO Driver {id:?} exit {status}"));
            return if status.success() {
                Ok(())
            } else {
                Err(format!("native driver {id:?} failed: {status}"))
            };
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stopping() || events.failed() {
            break;
        }
        std::thread::sleep(POLL_INTERVAL.min(remaining));
    }
    Ok(())
}
/// Retain an object above the standard I/O descriptors even when the caller starts
/// with stdin/stdout/stderr closed. Command's redirection must not replace it.
pub fn retained(file: File) -> Result<File> {
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// Copy one sealed admission fd into the unshared root before its read-only
/// remount. This function runs after fork and uses only fixed storage and syscalls.
unsafe fn copy_image(module: i32, name: &std::ffi::CStr, uid: u32, gid: u32) -> std::io::Result<()> {
    let fail = std::io::Error::last_os_error;
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    let seals = libc::fcntl(module, libc::F_GET_SEALS);
    if seals < 0 || seals & required != required {
        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
    }
    let target = libc::open(
        name.as_ptr(),
        libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
        0o600,
    );
    if target < 0 {
        return Err(fail());
    }
    // Anonymous shmem has no bindable user mount on all supported kernels.
    // Copy immutable admitted bytes inside the already bounded child group.
    // The allocation-free loop also bounds syscall work if admission is ever
    // called through another trusted embedding rather than the CLI.
    let mut offset = 0i64;
    let mut buffer = [0u8; 32768];
    loop {
        let n = libc::pread64(module, buffer.as_mut_ptr().cast(), buffer.len(), offset);
        if n < 0 {
            if fail().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(fail());
        }
        if n == 0 {
            break;
        }
        offset += n as i64;
        if offset as u64 > crate::manifest::libraries::MAX_IMAGE_BYTES {
            return Err(std::io::Error::from_raw_os_error(libc::EFBIG));
        }
        let mut done = 0usize;
        while done < n as usize {
            let wrote =
                libc::write(target, buffer.as_ptr().add(done).cast(), n as usize - done);
            if wrote < 0 {
                if fail().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(fail());
            }
            if wrote == 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            done += wrote as usize;
        }
    }
    // Service managers normally impose umask 0077. Pin the admitted
    // image to the final guest identity and exact read-only mode rather
    // than depending on the caller's mask or world-readable access.
    // The private mount is made read-only before credentials are dropped.
    if libc::fchown(target, uid, gid) != 0 || libc::fchmod(target, 0o400) != 0 {
        return Err(fail());
    }
    if libc::close(target) != 0 {
        return Err(fail());
    }
    Ok(())
}
fn spawn(runtime: &File, root: std::sync::Arc<crate::workload_fs::Root>, launch: &Launch, enrollment: File, extra: &[String], inherited: &[i32]) -> Result<(Child, File)> {
    use std::os::unix::fs::FileExt;
    let enrollment = retained(enrollment)?;
    let join = enrollment.as_raw_fd();
    if launch.libraries.len() != launch.process.libraries.ordered.len() {
        return Err("incomplete private Wasm image set".into());
    }
    crate::manifest::libraries::image_budget(&launch.module.0, &launch.libraries)?;
    let mut image_files = vec![(launch.module.0.as_raw_fd(), c"/tmp/tmp/wros-admitted.wasm".to_owned())];
    for (index, image) in launch.libraries.iter().enumerate() {
        // Before chroot the private root is mounted at /tmp; index is supervisor-generated.
        let name = std::ffi::CString::new(format!("/tmp{}", crate::manifest::libraries::image_path(index)))
            .map_err(|e| e.to_string())?;
        image_files.push((image.0.as_raw_fd(), name));
    }
    let exe = runtime.as_raw_fd();
    let mut magic = [0; 2];
    runtime.read_exact_at(&mut magic, 0).map_err(|e| e.to_string())?;
    // A trusted script's interpreter reopens the script descriptor after exec.
    // An ELF runtime consumes its inode in exec and needs no retained handle.
    let script = (magic == *b"#!").then_some(exe);
    let (uid, gid) = launch.process.identity.ok_or("missing guest identity")?;
    let parent = unsafe { libc::getpid() };
    let affinity = launch
        .process
        .cpus
        .as_ref()
        .map(crate::placement::Set::affinity);
    let mut command = Command::new(format!("/proc/self/fd/{exe}"));
    if extra.is_empty() {
        command.args(&launch.arguments);
    } else {
        if launch.arguments.len() < 2 || launch.arguments[launch.arguments.len() - 2] != "--run" {
            return Err("attachment requires a final VM run argument".into());
        }
        let (setup, run) = launch.arguments.split_at(launch.arguments.len() - 2);
        command.args(setup).args(extra).args(run);
    }
    let inherited = inherited.to_vec();
    let (mut mount_errors, errors) = std::io::pipe().map_err(|e| e.to_string())?;
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Every syscall below is allocation-free and async-signal-safe after fork.
    // cgroup enrollment is performed by the child (PID 0) before dropping root.
    unsafe {
        command.pre_exec(move || {
            let fail = || std::io::Error::last_os_error();
            let stage = |name: &[u8]| {
                libc::write(errors.as_raw_fd(), name.as_ptr().cast(), name.len());
            };
            stage(b"enroll ");
            if libc::write(join, b"0".as_ptr().cast(), 1) != 1 {
                return Err(fail());
            }
            if let Some(mask) = &affinity {
                if libc::sched_setaffinity(
                    0,
                    std::mem::size_of_val(mask.as_slice()),
                    mask.as_ptr().cast(),
                ) != 0
                {
                    return Err(fail());
                }
            }
            stage(b"namespace ");
            if libc::unshare(
                libc::CLONE_NEWNET
                    | libc::CLONE_NEWIPC
                    | libc::CLONE_NEWUTS
                    | libc::CLONE_NEWCGROUP
                    | libc::CLONE_NEWNS,
            ) != 0
            {
                return Err(fail());
            }
            if libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(fail());
            }
            stage(b"reopen mounts ");
            root.repin_mounts()?;
            stage(b"tmpfs ");
            let mount_flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            if libc::mount(
                c"wros-images".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                mount_flags,
                c"size=269484032,nr_inodes=1024,mode=0755".as_ptr().cast(),
            ) != 0
            {
                return Err(fail());
            }
            stage(b"mounts ");
            root.mount(errors.as_raw_fd())?;
            stage(b"images ");
            for (image, name) in &image_files {
                copy_image(*image, name, uid, gid)?;
            }
            if libc::mount(
                std::ptr::null(),
                c"/tmp".as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_RDONLY | mount_flags,
                std::ptr::null(),
            ) != 0
            {
                return Err(fail());
            }
            stage(b"chroot ");
            if libc::chroot(c"/tmp".as_ptr()) != 0 || libc::chdir(c"/".as_ptr()) != 0 {
                return Err(fail());
            }
            stage(b"identity ");
            finish_child((uid, gid), parent, crate::containment::Role::Vm)?;
            stage(b"exec");
            for fd in inherited.iter().copied().chain(script) {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(fail());
                }
            }
            Ok(())
        });
    }
    let result = spawn_pinned(command, "VM");
    if let Err(error) = result {
        let mut detail = String::new();
        let _ = (&mut mount_errors).take(512).read_to_string(&mut detail);
        return Err(if detail.is_empty() { error } else { format!("{error} ({detail})") });
    }
    result
}

/// Common allocation-free restrictions installed in the child before exec.
/// The child has already enrolled in its cgroup and entered its namespaces.
pub(crate) unsafe fn finish_child((uid, gid): (u32, u32), parent: libc::pid_t, role: crate::containment::Role) -> std::io::Result<()> {
    let fail = std::io::Error::last_os_error;
    if libc::setsid() < 0 {
        return Err(fail());
    }
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let files = libc::rlimit {
        rlim_cur: 256,
        rlim_max: 256,
    };
    if libc::setrlimit(libc::RLIMIT_CORE, &core) != 0
        || libc::setrlimit(libc::RLIMIT_NOFILE, &files) != 0
    {
        return Err(fail());
    }
    libc::umask(0o077);
    // Libraries that reopen an inherited pipe through /proc/self/fd must
    // see the final guest owner. Both pipe ends remain pinned by descriptors.
    for fd in [1, 2] {
        if libc::fchown(fd, uid, gid) != 0 {
            return Err(fail());
        }
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        || libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0
    {
        return Err(fail());
    }
    if libc::setgroups(0, std::ptr::null()) != 0
        || libc::setresgid(gid, gid, gid) != 0
        || libc::setresuid(uid, uid, uid) != 0
    {
        return Err(fail());
    }
    // Credential changes clear PDEATHSIG, so arm it afterwards and close the
    // race by checking the original parent. A dead supervisor cannot authorize exec.
    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
        || libc::getppid() != parent
    {
        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
    }
    if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
        return Err(fail());
    }
    crate::containment::restrict_workload(role)?;
    if libc::syscall(
        libc::SYS_close_range,
        3u32,
        u32::MAX,
        libc::CLOSE_RANGE_CLOEXEC,
    ) != 0
    {
        return Err(fail());
    }
    Ok(())
}

pub(crate) fn spawn_pinned(mut command: Command, role: &str) -> Result<(Child, File)> {
    let mut child = command
        .spawn()
        .map_err(|e| format!("{role} admission before exec failed: {e}"))?;
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
    if pidfd < 0 {
        let e = std::io::Error::last_os_error().to_string();
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let pidfd = unsafe { File::from_raw_fd(pidfd) };
    for fd in [
        child.stdout.as_ref().unwrap().as_raw_fd(),
        child.stderr.as_ref().unwrap().as_raw_fd(),
    ] {
        if let Err(e) = nonblocking(fd) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e);
        }
    }
    Ok((child, pidfd))
}
/// Combined stdout and stderr disclosure limit for one admitted VM generation.
#[derive(Default)]
struct DiagnosticBudget {
    retained: usize,
    reported_loss: bool,
}

impl DiagnosticBudget {
    fn admit(&mut self, read: usize) -> (usize, bool) {
        const LIMIT: usize = 8192;
        let keep = read.min(LIMIT - self.retained);
        self.retained += keep;
        let first_loss = keep < read && !self.reported_loss;
        self.reported_loss |= first_loss;
        (keep, first_loss)
    }
}

fn output(child: &mut Child, role: &str, id: &str, generation: u64, budget: &mut DiagnosticBudget, events: &Events) {
    let mut buffer = [0u8; 4096];
    // Bound work per stream even while the other stream or another VM is busy.
    for (stream, pipe) in [
        ("stdout", child.stdout.as_mut().map(|v| v as &mut dyn Read)),
        ("stderr", child.stderr.as_mut().map(|v| v as &mut dyn Read)),
    ] {
        let Some(pipe) = pipe else { continue };
        for _ in 0..4 {
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let (keep, first_loss) = budget.admit(n);
                    if keep > 0 {
                        events.send(format!(
                            "INFO {role} {id:?} diagnostic generation {generation} {stream} {:?}",
                            String::from_utf8_lossy(&buffer[..keep])
                        ));
                    }
                    if first_loss {
                        events.send(format!(
                            "WARNING {role} {id:?} generation {generation} diagnostic byte limit reached on {stream}; subsequent output omitted"
                        ));
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    }
}
impl Session<'_> {
    fn check_start(&mut self) -> Result<()> {
        if stopping() {
            if let Some(journal) = &mut self.journal {
                journal.stop(false)?;
            }
            return Err("operator stop before VM start".into());
        }
        if self.events.failed() {
            return Err("audit failure before VM start".into());
        }
        Ok(())
    }

    fn start(&mut self, index: usize, runtime: &File) -> Result<()> {
        self.check_start()?;
        let slot = &mut self.slots[index];
        let generation = if !slot.started {
            slot.state.operator_start()
        } else {
            slot.state.recover(slot.generation)
        }
        .ok_or("restart state denied")?;
        if let Some(journal) = &mut self.journal {
            journal.begin(
                &self.launches[index].process.id,
                generation,
                slot.started,
                self.launches[index].process.restart_limit,
            )?;
        }
        self.hierarchy.children[index].drain(Duration::from_secs(2))?;
        self.hierarchy.children[index].verify_placement(&self.launches[index].process)?;
        let enrollment = self.hierarchy.children[index].enrollment()?;
        self.check_start()?;
        let launch = &self.launches[index];
        let mut bootstraps = Vec::with_capacity(launch.drivers.len());
        let mut arguments = Vec::new();
        let mut inherited = Vec::new();
        for (driver, group) in launch.drivers.iter().zip(self.driver_groups[index].clone()) {
            self.check_start()?;
            let group = &self.hierarchy.children[group];
            group.drain(STOP_SETTLE)?;
            let ((provider, provider_pidfd), bootstrap) = crate::driver::start(driver, group.enrollment()?)?;
            let provider_id = provider.id();
            // Take ownership before any subsequent provider, VM or bootstrap can fail.
            self.slots[index].drivers.push(RunningDriver {
                child: Some(provider), pidfd: Some(provider_pidfd), ended: None,
                output: DiagnosticBudget::default(),
            });
            self.events.send(format!(
                "INFO Driver {:?} passed launch signature policy {:?}; PID {} in its dedicated cgroup",
                driver.artifact.id, driver.admission.verdict(), provider_id,
            ));
            let (route_args, route_fds) = bootstrap.vm_arguments(driver, &launch.process.id);
            self.events.send(format!("INFO VM {:?} extra driver CLI {:?}", launch.process.id, route_args));
            arguments.extend(route_args);
            inherited.extend(route_fds);
            bootstraps.push(bootstrap);
        }
        self.check_start()?;
        let (child, pidfd) = spawn(runtime, self.roots[index].clone(), launch, enrollment, &arguments, &inherited)?;
        let child_id = child.id();
        self.slots[index].child = Some(child);
        self.slots[index].pidfd = Some(pidfd);
        for (driver, bootstrap) in launch.drivers.iter().zip(bootstraps) {
            self.check_start()?;
            bootstrap.deliver(self.slots[index].child.as_ref().unwrap(), launch.process.identity.unwrap())?;
            self.events.send(format!("INFO Driver {:?} bootstrap delivered for authenticated TLS", driver.artifact.id));
        }
        self.events.send(format!(
            "INFO VM {:?} generation {} started with PID {}, no motion authority",
            launch.process.id, generation, child_id
        ));
        let slot = &mut self.slots[index];
        slot.generation = generation;
        slot.started = true;
        slot.next = None;
        slot.output = DiagnosticBudget::default();
        Ok(())
    }

    fn reap_exited(&mut self, diagnostics: bool) -> Result<bool> {
        let mut all_reaped = true;
        for (i, slot) in self.slots.iter_mut().enumerate() {
            for (driver, launch) in slot.drivers.iter_mut().zip(&self.launches[i].drivers) {
                if let Some(child) = &mut driver.child {
                    if diagnostics {
                        output(child, "Driver", &launch.artifact.id,
                               slot.generation, &mut driver.output, self.events);
                    }
                    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                        driver.child = None;
                        driver.pidfd = None;
                    } else {
                        all_reaped = false;
                    }
                }
            }
            if let Some(child) = &mut slot.child {
                if diagnostics {
                    output(
                        child,
                        "VM",
                        &self.launches[i].process.id,
                        slot.generation,
                        &mut slot.output,
                        self.events,
                    );
                }
                if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                    slot.child = None;
                    slot.pidfd = None;
                } else {
                    all_reaped = false;
                }
            }
        }
        Ok(all_reaped)
    }

    fn wait_for_shutdown(&mut self, until: Instant, whole_tree: bool) -> Result<bool> {
        loop {
            if self.reap_exited(true)? && (!whole_tree || self.hierarchy.empty()?) {
                return Ok(true);
            }
            let remaining = until.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            std::thread::sleep(POLL_INTERVAL.min(remaining));
        }
    }

    fn force_stop(&mut self) -> Result<()> {
        let killed = self.hierarchy.kill();
        if killed.is_err() {
            for slot in &self.slots {
                for fd in slot.pidfd.iter().chain(slot.drivers.iter().filter_map(|d| d.pidfd.as_ref())) {
                    signal(fd, libc::SIGKILL);
                }
            }
        }
        if !self.wait_for_shutdown(Instant::now() + STOP_SETTLE, true)? {
            return Err("deployment cgroup or direct children did not settle; supervisor intervention required".into());
        }
        killed
    }

    fn shutdown(&mut self) -> Result<()> {
        let grace = Instant::now() + STOP_GRACE;
        for slot in &mut self.slots {
            slot.state.operator_stop();
            slot.next = None;
            if let Some(fd) = &slot.pidfd {
                signal(fd, libc::SIGTERM);
            }
            for fd in slot.drivers.iter().filter_map(|driver| driver.pidfd.as_ref()) {
                signal(fd, libc::SIGTERM);
            }
        }
        let graceful = self.wait_for_shutdown(grace, false);
        self.force_stop()?;
        graceful?;
        Ok(())
    }
}

pub fn run(runtime: &Path, cgroup: &Path, deployment: &str, launches: &[Launch]) -> Result<()> {
    run_with_state(runtime, cgroup, deployment, launches, None)
}
pub fn run_with_state(
    runtime: &Path,
    cgroup: &Path,
    deployment: &str,
    launches: &[Launch],
    journal: Option<&mut crate::state::Journal>,
) -> Result<()> {
    let identities = reserve(cgroup, deployment, launches)?;
    run_reserved(runtime, cgroup, deployment, launches, journal, &identities)
}

fn identities(launches: &[Launch]) -> Result<Vec<(u32, u32)>> {
    let mut ids = Vec::with_capacity(launches.len() * 2);
    for launch in launches {
        ids.push(launch.process.identity.ok_or("missing VM identity")?);
        for driver in &launch.drivers {
            ids.push(driver.artifact.attachment.as_ref().ok_or("missing driver attachment")?.identity);
        }
    }
    Ok(ids)
}

pub fn reserve(cgroup: &Path, deployment: &str, launches: &[Launch]) -> Result<crate::ownership::Reservations> {
    crate::ownership::claim_ids(cgroup, deployment, &identities(launches)?, &[])
}
/// The CLI acquires identities before reclaiming old groups or consuming a
/// durable start authorization. Retain that same proof through final shutdown;
/// reacquiring here would either race recovery or conflict with our own locks.
pub fn run_reserved(
    runtime: &Path,
    cgroup: &Path,
    deployment: &str,
    launches: &[Launch],
    mut journal: Option<&mut crate::state::Journal>,
    identities: &crate::ownership::Reservations,
) -> Result<()> {
    identities.check_ids(cgroup, deployment, self::identities(launches)?)?;
    if launches.iter().any(|l| !l.drivers.is_empty())
        && (journal.is_some() || launches.iter().any(|l| l.process.boot_start || l.process.crash_restart))
    {
        return Err("native driver launch requires explicit supervision without automatic restart".into());
    }
    let _signals = Signals::install()?;
    let events = Events::new()?;
    events.send(format!("INFO Host UID/GID reservations held in {} for deployment {:?}; no cross-deployment takeover after manager exit", crate::ownership::DIRECTORY, deployment));
    events.send("INFO Every VM requires kernel device filtering: /dev/null read/write; /dev/zero, /dev/random and /dev/urandom read only; all other device opens and all mknod denied".into());
    let result = supervise(
        runtime,
        cgroup,
        deployment,
        launches,
        &events,
        journal.as_deref_mut(),
    );
    let logged = events.finish();
    let result = result.and(logged);
    if result.is_err() {
        if let Some(journal) = journal {
            journal.stop(!stopping())?;
        }
    }
    result
}
fn supervise(
    runtime: &Path,
    cgroup: &Path,
    deployment: &str,
    launches: &[Launch],
    events: &Events,
    journal: Option<&mut crate::state::Journal>,
) -> Result<()> {
    let runtime = retained(File::open(runtime).map_err(|e| e.to_string())?)?;
    let libraries = crate::workload_fs::Libraries::inspect(&runtime)?;
    let roots = launches.iter().map(|launch| {
        let identity = launch.process.identity.ok_or("missing VM identity")?;
        crate::workload_fs::Root::prepare(&libraries, &launch.arguments, identity).map(std::sync::Arc::new)
    }).collect::<Result<Vec<_>>>()?;
    let mut workloads = launches.iter().map(|l| Workload::from(&l.process)).collect::<Vec<_>>();
    let mut driver_groups = Vec::with_capacity(launches.len());
    for launch in launches {
        let first = workloads.len();
        for driver in &launch.drivers {
            workloads.push(Workload::driver(&driver.artifact)?);
        }
        driver_groups.push(first..workloads.len());
    }
    let hierarchy = Hierarchy::create_workloads(cgroup, deployment, &workloads)?;
    let slots = launches
        .iter()
        .map(|l| {
            let entry = journal
                .as_ref()
                .map(|j| j.entry(&l.process.id))
                .transpose()?;
            let previous = entry.map_or(0, |e| e.generation);
            Ok(Running {
                child: None,
                pidfd: None,
                state: Instance::after_generation(l.process.crash_restart, previous),
                generation: previous,
                restarts: entry.map_or(0, |e| e.restarts),
                next: None,
                failed: false,
                output: DiagnosticBudget::default(),
                started: false,
                drivers: Vec::with_capacity(l.drivers.len()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut session = Session {
        hierarchy,
        launches,
        slots,
        events,
        journal,
        driver_groups,
        roots,
    };
    match monitor(&mut session, launches, &runtime, events) {
        Ok(()) => Ok(()),
        Err(error) => match session.force_stop() {
            Ok(()) => Err(error),
            Err(cleanup) => Err(format!("{error}; deployment cleanup failed: {cleanup}")),
        },
    }
}

fn monitor(session: &mut Session<'_>, launches: &[Launch], runtime: &File, events: &Events) -> Result<()> {
    for i in 0..launches.len() {
        session.start(i, runtime)?;
    }
    loop {
        if STOP.load(Ordering::SeqCst) {
            if let Some(journal) = &mut session.journal {
                journal.stop(false)?;
            }
            session.shutdown()?;
            events.send(
                "INFO Operator stop completed; no automatic restart in this invocation".into(),
            );
            return Ok(());
        }
        if events.failed() {
            session.shutdown()?;
            return Err("audit saturation or failure stopped the deployment".into());
        }
        for (i, launch) in launches.iter().enumerate() {
            let slot = &mut session.slots[i];
            for (driver, provider) in slot.drivers.iter_mut().zip(&launch.drivers) {
                if let Some(child) = &mut driver.child {
                    let id = &provider.artifact.id;
                    output(child, "Driver", id, slot.generation, &mut driver.output, events);
                    if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                        output(child, "Driver", id, slot.generation, &mut driver.output, events);
                        driver.child = None;
                        driver.pidfd = None;
                        events.send(format!("INFO Driver {id:?} exit {status}"));
                        if !status.success() {
                            return Err(format!("native driver {id:?} failed: {status}"));
                        }
                        driver.ended = Some(Instant::now());
                    }
                }
            }
            if let Some(child) = &mut slot.child {
                output(child, "VM", &launch.process.id, slot.generation, &mut slot.output, events);
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    if let Some(journal) = &mut session.journal {
                        journal.exited(&launch.process.id, status.success())?;
                    }
                    output(child, "VM", &launch.process.id, slot.generation, &mut slot.output, events);
                    events.send(format!(
                        "INFO VM {:?} generation {} exit {status}",
                        launch.process.id, slot.generation
                    ));
                    events.send(format!(
                        "INFO VM {:?} resource events {}",
                        launch.process.id,
                        session.hierarchy.children[i].accounting()?
                    ));
                    slot.child = None;
                    slot.pidfd = None;
                    session.hierarchy.children[i].drain(Duration::from_secs(2))?;
                    let deadline = Instant::now() + DRIVER_CLOSE_GRACE;
                    for ((driver, provider), group) in slot.drivers.iter_mut().zip(&launch.drivers).zip(session.driver_groups[i].clone()) {
                        let id = &provider.artifact.id;
                        if status.success() {
                            // The VM can return immediately after sending RELEASE.
                            // Give the provider a bounded window to close and flush diagnostics.
                            finish_driver(driver, id, slot.generation, events, deadline)?;
                        }
                        session.hierarchy.children[group].drain(Duration::from_secs(2))?;
                        if let Some(provider) = &mut driver.child {
                            let _ = provider.wait().map_err(|e| e.to_string())?;
                            output(provider, "Driver", id, slot.generation, &mut driver.output, events);
                        }
                    }
                    slot.drivers.clear();
                    if status.success() {
                        slot.state.operator_stop();
                    } else {
                        slot.state.fault(slot.generation);
                        if launch.process.crash_restart
                            && slot.restarts < launch.process.restart_limit
                        {
                            slot.restarts += 1;
                            slot.next = Some(
                                Instant::now()
                                    + Duration::from_millis(u64::from(
                                        launch.process.restart_delay_ms,
                                    )),
                            );
                            events.send(format!(
                                "INFO XML-authorized cold restart {:?}: attempt {} of {}",
                                launch.process.id, slot.restarts, launch.process.restart_limit
                            ));
                        } else {
                            slot.failed = true;
                        }
                    }
                }
            }
            // An adapter can finish its RELEASE just before the VM returns.
            // A VM that stays live after loss of its provider cannot keep running.
            if slot.child.is_some() && slot.drivers.iter().filter_map(|d| d.ended)
                .any(|end| end.elapsed() >= DRIVER_CLOSE_GRACE)
            {
                return Err("driver exited while its VM remained active".into());
            }
            if session.slots[i]
                .next
                .is_some_and(|when| Instant::now() >= when)
            {
                session.start(i, runtime)?;
            }
        }
        if session
            .slots
            .iter()
            .all(|s| s.child.is_none() && s.next.is_none())
        {
            return if session.slots.iter().any(|s| s.failed) {
                Err("deployment ended with failed VM instances".into())
            } else {
                Ok(())
            };
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::DiagnosticBudget;

    #[test]
    fn loss_is_reported_once_on_the_first_omitted_byte() {
        let mut budget = DiagnosticBudget::default();
        assert_eq!(budget.admit(8191), (8191, false));
        assert_eq!(budget.admit(1), (1, false));
        assert_eq!(budget.admit(0), (0, false));
        assert_eq!(budget.admit(1), (0, true));
        assert_eq!(budget.admit(usize::MAX), (0, false));

        let mut restarted = DiagnosticBudget::default();
        assert_eq!(restarted.admit(8193), (8192, true));
        assert_eq!(restarted.admit(23), (0, false));
    }
}
