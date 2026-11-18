//! Bounded local VM supervisor. It receives fully admitted images and reviewed
//! argument vectors. Enrollment, namespace creation, identity drop and immutable
//! descriptor inheritance complete before the first VM instruction executes.
//! Native provider launch, recovery Wasm and live control are separate capabilities;
//! this entry point refuses manifests requiring those unfinished capabilities.
use crate::{
    audit::Events,
    cgroup::Hierarchy,
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
    pub arguments: Vec<String>,
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
}
struct Session<'a> {
    hierarchy: Hierarchy,
    launches: &'a [Launch],
    slots: Vec<Running>,
    events: &'a Events,
    journal: Option<&'a mut crate::state::Journal>,
}
impl Drop for Session<'_> {
    fn drop(&mut self) {
        // Groups are exclusively ours. Kill descendants before waiting for direct
        // children; PID handles avoid targeting an unrelated reused process ID.
        for group in &self.hierarchy.children {
            let _ = group.kill();
        }
        for slot in &mut self.slots {
            if let Some(child) = &mut slot.child {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}
fn nonblocking(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
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
fn spawn(runtime: &File, launch: &Launch, enrollment: File) -> Result<(Child, File)> {
    let enrollment = retained(enrollment)?;
    let join = enrollment.as_raw_fd();
    let module = launch.module.0.as_raw_fd();
    let exe = runtime.as_raw_fd();
    let (uid, gid) = launch.process.identity.ok_or("missing guest identity")?;
    let parent = unsafe { libc::getpid() };
    let affinity = launch
        .process
        .cpus
        .as_ref()
        .map(crate::placement::Set::affinity);
    let mut command = Command::new(format!("/proc/self/fd/{exe}"));
    command
        .args(&launch.arguments)
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
            let mount_flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
            if libc::mount(
                c"wros-images".as_ptr(),
                c"/tmp".as_ptr(),
                c"tmpfs".as_ptr(),
                mount_flags,
                c"size=269484032,nr_inodes=32,mode=0755".as_ptr().cast(),
            ) != 0
            {
                return Err(fail());
            }
            let target = libc::open(
                c"/tmp/wros-admitted.wasm".as_ptr(),
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
                if offset > 268435456 {
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
            crate::containment::pin_namespaces()?;
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                return Err(fail());
            }
            if libc::fcntl(exe, libc::F_SETFD, 0) != 0 {
                return Err(fail());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("VM admission before exec failed: {e}"))?;
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

fn output(child: &mut Child, id: &str, generation: u64, budget: &mut DiagnosticBudget, events: &Events) {
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
                            "INFO VM {id:?} diagnostic generation {generation} {stream} {:?}",
                            String::from_utf8_lossy(&buffer[..keep])
                        ));
                    }
                    if first_loss {
                        events.send(format!(
                            "WARNING VM {id:?} generation {generation} diagnostic byte limit reached on {stream}; subsequent output omitted"
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
    fn start(&mut self, index: usize, runtime: &File) -> Result<()> {
        if STOP.load(Ordering::SeqCst) || self.events.failed() {
            return Err("operator stop or audit failure before VM start".into());
        }
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
        let (child, pidfd) = spawn(
            runtime,
            &self.launches[index],
            self.hierarchy.children[index].enrollment()?,
        )?;
        self.events.send(format!(
            "INFO VM {:?} generation {} started with PID {}, no motion authority",
            self.launches[index].process.id,
            generation,
            child.id()
        ));
        slot.child = Some(child);
        slot.pidfd = Some(pidfd);
        slot.generation = generation;
        slot.started = true;
        slot.next = None;
        slot.output = DiagnosticBudget::default();
        Ok(())
    }
    fn shutdown(&mut self) -> Result<()> {
        for slot in &mut self.slots {
            slot.state.operator_stop();
            slot.next = None;
            if let Some(fd) = &slot.pidfd {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGTERM,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                }
            }
        }
        let end = Instant::now() + Duration::from_secs(2);
        while Instant::now() < end {
            let mut pending = false;
            for (i, slot) in self.slots.iter_mut().enumerate() {
                if let Some(child) = &mut slot.child {
                    output(
                        child,
                        &self.launches[i].process.id,
                        slot.generation,
                        &mut slot.output,
                        self.events,
                    );
                    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                        slot.child = None;
                        slot.pidfd = None;
                    } else {
                        pending = true;
                    }
                }
            }
            if !pending {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        for group in &self.hierarchy.children {
            group.drain(Duration::from_secs(2))?;
        }
        for slot in &mut self.slots {
            if let Some(mut child) = slot.child.take() {
                child.wait().map_err(|e| e.to_string())?;
            }
            slot.pidfd = None;
        }
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
    let identities = crate::ownership::claim(
        cgroup,
        deployment,
        &launches.iter().map(|l| &l.process).collect::<Vec<_>>(),
    )?;
    run_reserved(runtime, cgroup, deployment, launches, journal, &identities)
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
    identities.check(
        cgroup,
        deployment,
        &launches.iter().map(|l| &l.process).collect::<Vec<_>>(),
    )?;
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
            journal.stop(true)?;
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
    let processes = launches.iter().map(|l| &l.process).collect::<Vec<_>>();
    let hierarchy = Hierarchy::create(cgroup, deployment, &processes)?;
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
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut session = Session {
        hierarchy,
        launches,
        slots,
        events,
        journal,
    };
    for i in 0..launches.len() {
        session.start(i, &runtime)?;
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
            if let Some(child) = &mut slot.child {
                output(child, &launch.process.id, slot.generation, &mut slot.output, events);
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    if let Some(journal) = &mut session.journal {
                        journal.exited(&launch.process.id, status.success())?;
                    }
                    output(child, &launch.process.id, slot.generation, &mut slot.output, events);
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
            if session.slots[i]
                .next
                .is_some_and(|when| Instant::now() >= when)
            {
                session.start(i, &runtime)?;
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
        std::thread::sleep(Duration::from_millis(5));
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
