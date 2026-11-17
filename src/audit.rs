//! Bounded runtime audit delivery. A slow log consumer must never block process
//! termination or keep a failed generation alive. Saturation stops deployment;
//! final output that cannot drain is reported as an unsuccessful invocation.
use crate::manifest::Result;
use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc::{sync_channel, SyncSender},
    Arc,
};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub struct Events {
    sender: Option<SyncSender<String>>,
    failed: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl Events {
    pub fn new() -> Result<Self> {
        let fd = unsafe { libc::fcntl(1, libc::F_DUPFD_CLOEXEC, 3) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let mut output = unsafe { File::from_raw_fd(fd) };
        let (sender, receiver) = sync_channel::<String>(32);
        let failed = Arc::new(AtomicBool::new(false));
        let failure = Arc::clone(&failed);
        let worker = std::thread::Builder::new()
            .name("wros-audit".into())
            .spawn(move || {
                for message in receiver {
                    if output.write_all(message.as_bytes()).is_err() {
                        failure.store(true, Ordering::Release);
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            sender: Some(sender),
            failed,
            worker: Some(worker),
        })
    }
    pub fn send(&self, mut message: String) {
        if message.len() > 32767 {
            self.failed.store(true, Ordering::Release);
            return;
        }
        message.push('\n');
        if self
            .sender
            .as_ref()
            .is_none_or(|sender| sender.try_send(message).is_err())
        {
            self.failed.store(true, Ordering::Release);
        }
    }
    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub fn finish(mut self) -> Result<()> {
        self.sender.take();
        let end = Instant::now() + Duration::from_millis(500);
        while self.worker.as_ref().is_some_and(|t| !t.is_finished()) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(5));
        }
        let worker = self.worker.take().unwrap();
        if !worker.is_finished() {
            return Err("runtime audit sink did not drain; VM shutdown has completed".into());
        }
        if worker.join().is_err() || self.failed() {
            return Err("runtime audit delivery failed; VM shutdown has completed".into());
        }
        Ok(())
    }
}
