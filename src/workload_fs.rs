//! Build the VM's private root from pinned administrator-controlled inputs.
//! No host working directory, writable shared mount or named IPC object is
//! mounted. The one writable directory is the assigned VM's WSEA rollback store.
use crate::manifest::Result;
use crate::verification::protected_path;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

const READ_ONLY: libc::c_ulong = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV;
const DATA: libc::c_ulong = READ_ONLY | libc::MS_NOEXEC;

fn cpath(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| "NUL in VM filesystem path".into())
}

fn staged(path: &Path) -> Result<CString> {
    let relative = path.strip_prefix("/").map_err(|_| "expected an absolute VM path")?;
    if relative.as_os_str().is_empty() || !relative.components().all(|p| matches!(p, Component::Normal(_))) {
        return Err("invalid path in the VM filesystem".into());
    }
    cpath(&Path::new("/tmp").join(relative))
}

fn pin(path: &Path) -> Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_PATH | libc::O_NOFOLLOW)
        .open(path).map_err(|e| format!("pin {path:?}: {e}"))?;
    crate::supervisor::retained(file)
}

fn mount_id(path: &Path) -> Result<u64> {
    let path = cpath(path)?;
    let mut info: libc::statx = unsafe { std::mem::zeroed() };
    let flags = libc::AT_SYMLINK_NOFOLLOW | libc::AT_NO_AUTOMOUNT;
    if unsafe { libc::statx(libc::AT_FDCWD, path.as_ptr(), flags, libc::STATX_MNT_ID, &mut info) } != 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if info.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err("kernel cannot verify workload filesystem mount boundaries".into());
    }
    Ok(info.stx_mnt_id)
}

// A nonrecursive bind excludes submounts. Reject special files and mutable
// content before exposing a directory shared by several read-only instances.
pub(crate) fn immutable_tree(root: &Path, max_entries: usize) -> Result<()> {
    let mount = mount_id(root)?;
    let mut pending = vec![(root.to_owned(), 0)];
    let mut count = 0;
    while let Some((dir, depth)) = pending.pop() {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            count += 1;
            if crate::supervisor::stopping() {
                return Err("operator stop cancelled workload filesystem admission".into());
            }
            if count > max_entries || depth >= 32 {
                return Err("immutable workload tree exceeds the validation budget".into());
            }
            let info = entry.metadata().map_err(|e| e.to_string())?;
            let kind = info.file_type();
            if info.uid() != 0 || mount_id(&entry.path())? != mount
                || (!kind.is_symlink() && info.mode() & 0o022 != 0)
                || !(kind.is_file() || kind.is_dir() || kind.is_symlink())
            {
                return Err(format!("untrusted or special entry in workload filesystem {:?}", entry.path()));
            }
            if kind.is_dir() {
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct Mount {
    pin: Arc<File>,
    source: CString,
    host_path: CString,
    object: (libc::dev_t, libc::ino64_t),
    target: CString,
    flags: libc::c_ulong,
    directory: bool,
}

impl Mount {
    fn new(file: File, path: &Path, flags: libc::c_ulong) -> Result<Self> {
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let host_path = cpath(&fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(|e| e.to_string())?)?;
        let info = file.metadata().map_err(|e| e.to_string())?;
        Ok(Self { pin: Arc::new(file), source, host_path, object: (info.dev(), info.ino()), target: staged(path)?, flags, directory: info.is_dir() })
    }
}

pub(crate) struct Libraries(BTreeMap<PathBuf, Mount>);
impl Libraries {
    pub(crate) fn inspect(runtime: &File) -> Result<Self> {
        use std::os::unix::fs::FileExt;
        let mut mounts = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for name in ["/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/local/lib"] {
            let path = Path::new(name);
            let real = match path.canonicalize() {
                Ok(real) => real,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
            };
            if seen.insert(real.clone()) {
                protected_path(&real, true)?;
                immutable_tree(&real, 262144)?;
            }
            mounts.insert(path.to_owned(), Mount::new(pin(&real)?, path, READ_ONLY)?);
        }
        for name in ["/etc/ld.so.cache", "/etc/ssl/openssl.cnf"] {
            let path = Path::new(name);
            if path.try_exists().map_err(|e| e.to_string())? {
                let real = protected_path(&path.canonicalize().map_err(|e| e.to_string())?, false)?;
                mounts.insert(path.to_owned(), Mount::new(pin(&real)?, path, DATA)?);
            }
        }
        let mut header = [0; 256];
        let size = runtime.read_at(&mut header, 0).map_err(|e| e.to_string())?;
        if header[..size].starts_with(b"#!") {
            let line = header[2..size].split(|c| *c == b'\n').next().unwrap();
            let interpreter = std::str::from_utf8(line).map_err(|_| "invalid runtime interpreter")?
                .split_ascii_whitespace().next().ok_or("missing runtime interpreter")?;
            let path = Path::new(interpreter);
            if !path.is_absolute() { return Err("runtime interpreter must be absolute".into()); }
            let real = protected_path(&path.canonicalize().map_err(|e| e.to_string())?, false)?;
            mounts.insert(path.to_owned(), Mount::new(pin(&real)?, path, READ_ONLY)?);
        }
        for (name, minor) in [("null", 3), ("zero", 5), ("random", 8), ("urandom", 9)] {
            let path = Path::new("/dev").join(name);
            let file = pin(&path)?;
            let info = file.metadata().map_err(|e| e.to_string())?;
            if !info.file_type().is_char_device() || info.rdev() != libc::makedev(1, minor) {
                return Err(format!("unexpected VM device at {path:?}"));
            }
            mounts.insert(path.clone(), Mount::new(file, &path, libc::MS_NOSUID | libc::MS_NOEXEC)?);
        }
        Ok(Self(mounts))
    }
}

pub(crate) struct Root {
    mounts: Vec<Mount>,
    directories: Vec<CString>,
}

impl Root {
    pub(crate) fn prepare(libraries: &Libraries, argv: &[String], identity: (u32, u32)) -> Result<Self> {
        let mut mounts = libraries.0.clone();
        for args in argv.windows(4).filter(|args| args[0] == "--secure" && matches!(args[1].as_str(), "module" | "named-module")) {
            let policy = protected_path(Path::new(&args[3]), false)?;
            let body = crate::manifest::xml_contents(File::open(&policy).map_err(|e| e.to_string())?)?;
            let field = |prefix: &str| -> Result<PathBuf> {
                let mut values = body.lines().filter_map(|s| s.strip_prefix(prefix));
                let path = PathBuf::from(values.next().ok_or("missing WSEA filesystem input")?);
                if !path.is_absolute() || values.next().is_some() { return Err("invalid WSEA filesystem input".into()); }
                Ok(path)
            };
            let trust = protected_path(&field("trust_root=")?, false)?;
            let state = field("state_dir=")?;
            if state.canonicalize().map_err(|e| e.to_string())? != state {
                return Err("VM rollback directory must have a canonical path".into());
            }
            protected_path(state.parent().ok_or("invalid VM rollback directory")?, true)?;
            let file = pin(&state)?;
            let info = file.metadata().map_err(|e| e.to_string())?;
            if !info.is_dir() || (info.uid(), info.gid()) != identity || info.mode() & 0o7777 != 0o700 {
                return Err("VM rollback directory must be owned exclusively by its workload with mode 0700".into());
            }
            let state_mount = mount_id(&state)?;
            for (i, entry) in fs::read_dir(&state).map_err(|e| e.to_string())?.enumerate() {
                let entry = entry.map_err(|e| e.to_string())?;
                let info = entry.metadata().map_err(|e| e.to_string())?;
                if i >= 4096 || mount_id(&entry.path())? != state_mount || !info.is_file() || info.nlink() != 1
                    || (info.uid(), info.gid()) != identity || info.mode() & 0o077 != 0 {
                    return Err("invalid shared or special file in the VM rollback directory".into());
                }
            }
            for (path, file, flags) in [
                (&policy, pin(&policy)?, DATA), (&trust, pin(&trust)?, DATA),
                (&state, file, libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC),
            ] {
                if let Some(mount) = mounts.get(path) {
                    if mount.flags == flags && !libraries.0.contains_key(path) {
                        continue;
                    }
                }
                if Path::new(crate::supervisor::IMAGE_PATH).starts_with(path) || path.starts_with("/proc") || path.starts_with("/dev")
                    || mounts.keys().any(|other| path.starts_with(other) || other.starts_with(path)) {
                    return Err(format!("WSEA input collides with another VM mount: {path:?}"));
                }
                mounts.insert(path.clone(), Mount::new(file, path, flags)?);
            }
        }
        let mut directories = BTreeSet::from([PathBuf::from("/proc"), PathBuf::from("/tmp")]);
        for (path, mount) in &mounts {
            if mount.directory { directories.insert(path.clone()); }
            for ancestor in path.ancestors().skip(1).take_while(|a| *a != Path::new("/")) {
                directories.insert(ancestor.to_owned());
            }
        }
        Ok(Self { mounts: mounts.into_values().collect(), directories: directories.iter().map(|p| staged(p)).collect::<Result<_>>()? })
    }

    // unshare(CLONE_NEWNS) duplicates the mount tree. Linux refuses a bind
    // mount sourced from an FD pinned to the old namespace. Reopen each exact
    // inode in the clone before our private staging mount covers host paths.
    pub(crate) unsafe fn repin_mounts(&self) -> io::Result<()> {
        for mount in &self.mounts {
            let new_fd = libc::open(mount.host_path.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            if new_fd < 0 { return Err(io::Error::last_os_error()); }
            let mut info: libc::stat64 = std::mem::zeroed();
            if libc::fstat64(new_fd, &mut info) != 0 { return Err(io::Error::last_os_error()); }
            if (info.st_dev, info.st_ino) != mount.object { return Err(io::Error::from_raw_os_error(libc::ESTALE)); }
            if libc::dup3(new_fd, mount.pin.as_raw_fd(), libc::O_CLOEXEC) < 0 || libc::close(new_fd) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    // Called after fork in an already private mount namespace. All paths and
    // descriptor references live in the precomputed plan. The root is a fresh
    // tmpfs and no library symlink is followed when creating the mountpoints.
    pub(crate) unsafe fn mount(&self, errors: libc::c_int) -> io::Result<()> {
        let fail = |stage: &[u8], path: &std::ffi::CStr| {
            let error = io::Error::last_os_error();
            libc::write(errors, stage.as_ptr().cast(), stage.len());
            let bytes = path.to_bytes();
            libc::write(errors, bytes.as_ptr().cast(), bytes.len().min(256));
            error
        };
        libc::umask(0o022);
        for dir in &self.directories {
            if libc::mkdir(dir.as_ptr(), 0o755) != 0 { return Err(fail(b"mkdir ", dir)); }
        }
        for mount in &self.mounts {
            if !mount.directory {
                let fd = libc::open(mount.target.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC, 0o600);
                if fd < 0 || libc::close(fd) != 0 { return Err(fail(b"mountpoint ", &mount.target)); }
            }
        }
        for mount in &self.mounts {
            if libc::mount(mount.source.as_ptr(), mount.target.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) != 0 {
                return Err(fail(b"bind ", &mount.target));
            }
            if libc::mount(std::ptr::null(), mount.target.as_ptr(), std::ptr::null(), libc::MS_BIND | libc::MS_REMOUNT | mount.flags, std::ptr::null()) != 0 {
                return Err(fail(b"set mount flags ", &mount.target));
            }
        }
        if libc::mount(c"proc".as_ptr(), c"/tmp/proc".as_ptr(), c"proc".as_ptr(),
                DATA, c"hidepid=2,subset=pid".as_ptr().cast()) != 0 {
            return Err(fail(b"mount ", c"private procfs"));
        }
        Ok(())
    }
}
