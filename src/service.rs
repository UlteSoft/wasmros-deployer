//! Independent service supervision, with no shell or automatic installation.
//!
//! The service manager owns one bounded cgroup and places this process in its
//! `manager` child before exec. This module only prepares children of that exact
//! delegated root. Workloads remain descendants of the ultimate supervisor, so
//! a supervisor stop can kill the entire tree even after this manager dies.
//! Non-systemd platforms may supply the same checked layout and lifecycle
//! contract; merely naming an arbitrary cgroup does not satisfy the contract.
use crate::cgroup::{delegated_parent, open_at, owner, read, write};
use crate::manifest::{Deployment, Result};
use crate::placement::Set;
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};

pub struct Budget {
    pub memory: u64,
    pub tasks: u64,
    pub workload_memory: u64,
    pub workload_tasks: u64,
}
pub fn budget(plan: &Deployment) -> Result<Budget> {
    let manager = plan
        .supervisor
        .as_ref()
        .ok_or("managed execution requires a supervisor XML budget")?;
    if !plan.drivers.is_empty() {
        return Err("native provider execution is not yet qualified".into());
    }
    let mut memory = 0u64;
    let mut tasks = 0u64;
    for p in &plan.processes {
        if p.identity.is_none() {
            return Err("managed execution requires distinct non-root guest identities".into());
        }
        memory = memory
            .checked_add(p.memory_bytes)
            .ok_or("service memory overflow")?;
        tasks = tasks
            .checked_add(u64::from(p.pids))
            .ok_or("service task overflow")?;
    }
    Ok(Budget {
        // Bounded headroom for ultimate-manager control tasks and root metadata.
        memory: memory
            .checked_add(manager.memory_bytes)
            .and_then(|n| n.checked_add(4 * 1024 * 1024))
            .ok_or("service memory overflow")?,
        tasks: tasks
            .checked_add(u64::from(manager.pids))
            .and_then(|n| n.checked_add(4))
            .ok_or("service task overflow")?,
        workload_memory: memory,
        workload_tasks: tasks,
    })
}

/// Accept an exact future cgroup name even before the service exists. At run
/// time the opened directory, filesystem, owner and current membership are all
/// checked again. Relative paths, aliases and cgroup namespace roots fail closed.
pub fn root_path(path: &Path) -> Result<PathBuf> {
    let base = Path::new("/sys/fs/cgroup");
    if !path.is_absolute()
        || path == base
        || !path.starts_with(base)
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
        || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || path
            .as_os_str()
            .as_encoded_bytes()
            .iter()
            .any(|b| *b < 32 || *b == 127)
    {
        return Err("supervisor cgroup needs an exact absolute name below /sys/fs/cgroup".into());
    }
    Ok(path.to_path_buf())
}

fn no_children(group: &File) -> Result<()> {
    for entry in std::fs::read_dir(format!("/proc/self/fd/{}", group.as_raw_fd()))
        .map_err(|e| e.to_string())?
    {
        if entry
            .map_err(|e| e.to_string())?
            .file_type()
            .map_err(|e| e.to_string())?
            .is_dir()
        {
            return Err("manager cgroup must not contain delegated children".into());
        }
    }
    Ok(())
}
fn placement(group: &File, field: &str, desired: &Option<Set>) -> Result<()> {
    if let Some(desired) = desired {
        if !Set::parse(read(group, &format!("{field}.effective"))?.trim())?.contains(desired) {
            return Err("supervisor placement exceeds effective delegation".into());
        }
        write(group, field, &desired.to_string())?;
        if Set::parse(read(group, &format!("{field}.effective"))?.trim())? != *desired {
            return Err("supervisor placement differs from reviewed placement".into());
        }
    }
    Ok(())
}

/// Called with the durable approval lock held, before admission creates a
/// verifier or any VM. Never enroll this process elsewhere, alter an ancestor,
/// kill an old workload, or silently accept a different resource budget.
pub fn prepare(path: &Path, plan: &Deployment) -> Result<PathBuf> {
    let path = root_path(path)?;
    let b = budget(plan)?;
    let expected = path.join("manager");
    let proc = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?;
    let member = proc
        .trim()
        .strip_prefix("0::")
        .ok_or("managed execution needs unified cgroup membership")?;
    if proc.lines().count() != 1
        || Path::new("/sys/fs/cgroup").join(member.trim_start_matches('/')) != expected
    {
        return Err(
            "ultimate supervisor must place the manager in the exact manager subgroup".into(),
        );
    }
    let root = delegated_parent(&path)?;
    for (key, minimum) in [("memory.max", b.memory), ("pids.max", b.tasks)] {
        if read(&root, key)?
            .trim()
            .parse::<u64>()
            .map_err(|_| "ultimate supervisor must set finite memory/task limits")?
            < minimum
        {
            return Err(format!(
                "ultimate supervisor {key} is below the reviewed service budget"
            ));
        }
    }
    if read(&root, "memory.swap.max")?.trim() != "0"
        || read(&root, "memory.oom.group")?.trim() != "0"
    {
        return Err("service root requires zero swap and independent child OOM handling".into());
    }
    for entry in std::fs::read_dir(&path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if entry.file_type().map_err(|e| e.to_string())?.is_dir()
            && !matches!(
                entry.file_name().to_str(),
                Some("manager" | "workloads" | ".control")
            )
        {
            return Err("unexpected child in the delegated service root".into());
        }
    }
    let manager = open_at(&root, "manager", libc::O_RDONLY | libc::O_DIRECTORY)?;
    owner(&manager)?;
    no_children(&manager)?;
    if read(&manager, "cgroup.procs")?.trim() != std::process::id().to_string() {
        return Err("manager subgroup must contain only this process before admission".into());
    }
    let available = read(&root, "cgroup.controllers")?;
    let m = plan.supervisor.as_ref().unwrap();
    let need_placement = m.cpus.is_some()
        || m.memory_nodes.is_some()
        || plan
            .processes
            .iter()
            .any(|p| p.cpus.is_some() || p.memory_nodes.is_some());
    let required = if need_placement {
        &["cpu", "memory", "pids", "cpuset"][..]
    } else {
        &["cpu", "memory", "pids"][..]
    };
    for controller in required {
        if !available.split_whitespace().any(|s| s == *controller) {
            return Err(format!("ultimate supervisor did not delegate {controller}"));
        }
    }
    let enable = required
        .iter()
        .map(|s| format!("+{s}"))
        .collect::<Vec<_>>()
        .join(" ");
    write(&root, "cgroup.subtree_control", &enable)?;
    write(&manager, "memory.max", &m.memory_bytes.to_string())?;
    write(&manager, "memory.swap.max", "0")?;
    write(&manager, "memory.oom.group", "1")?;
    write(&manager, "pids.max", &m.pids.to_string())?;
    write(&manager, "cpu.max", &format!("{} 100000", m.cpu_micros))?;
    placement(&manager, "cpuset.mems", &m.memory_nodes)?;
    placement(&manager, "cpuset.cpus", &m.cpus)?;

    let created = unsafe { libc::mkdirat(root.as_raw_fd(), c"workloads".as_ptr(), 0o755) } == 0;
    if !created && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let workloads = open_at(&root, "workloads", libc::O_RDONLY | libc::O_DIRECTORY)?;
    owner(&workloads)?;
    if !read(&workloads, "cgroup.procs")?.trim().is_empty()
        || read(&workloads, "cgroup.type")?.trim() != "domain"
    {
        return Err("workload delegation must be an empty domain".into());
    }
    for (key, value) in [
        ("memory.max", b.workload_memory.to_string()),
        ("memory.swap.max", "0".into()),
        ("pids.max", b.workload_tasks.to_string()),
    ] {
        if !created && read(&workloads, key)?.trim() != value {
            return Err("existing workload budget differs from reviewed configuration".into());
        }
        write(&workloads, key, &value)?;
    }
    write(&workloads, "cgroup.subtree_control", &enable)?;
    Ok(path.join("workloads"))
}

/// Quote a systemd word and escape specifiers. The executable word has no
/// environment substitution; doubling its dollars would change its filename.
fn executable_word(value: &str) -> Result<String> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return Err("service argument exceeds bounds or contains a control character".into());
    }
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
/// Remaining words additionally undergo environment expansion. Double dollars
/// only here; neither this command nor any argument is passed through a shell.
fn word(value: &str) -> Result<String> {
    executable_word(&value.replace('$', "$$"))
}

/// Render, never install or enable, a systemd >=254 unit. The only command is
/// resume: missing approval, changed bytes or exhausted authority fail closed.
/// An alternate platform manager must enforce the same whole-tree lifecycle.
pub fn unit(
    plan: &Deployment,
    manifest: &Path,
    executable: &Path,
    options: &BTreeMap<String, PathBuf>,
) -> Result<String> {
    let b = budget(plan)?;
    let root = options
        .get("--supervisor-cgroup")
        .ok_or("service requires --supervisor-cgroup")?;
    if root_path(root)?
        != PathBuf::from(format!(
            "/sys/fs/cgroup/system.slice/wros-{}.service",
            plan.id
        ))
    {
        return Err(
            "systemd service root must be /sys/fs/cgroup/system.slice/wros-ID.service".into(),
        );
    }
    let mut args = vec![
        executable_word(executable.to_str().ok_or("non-UTF8 executable")?)?,
        word("resume")?,
        word(manifest.to_str().ok_or("non-UTF8 manifest")?)?,
    ];
    for name in [
        "--policy-root",
        "--cosign",
        "--scratch-directory",
        "--runtime",
        "--state-directory",
        "--supervisor-cgroup",
    ] {
        let value = options
            .get(name)
            .ok_or_else(|| format!("service requires {name}"))?;
        if !value.is_absolute() {
            return Err("service paths must be absolute".into());
        }
        args.push(word(name)?);
        args.push(word(value.to_str().ok_or("non-UTF8 service path")?)?);
    }
    Ok(format!("# Generated configuration; requires systemd >=254 and cgroup v2.\n# Install as wros-{}.service only after separate operator authorization.\n[Unit]\nDescription=WROS deployment {}\nAfter=local-fs.target\nStartLimitIntervalSec=60s\nStartLimitBurst=3\n\n[Service]\nType=exec\nUser=root\nGroup=root\nExecStart={}\nRestart=on-failure\nRestartPreventExitStatus=1\nRestartSec=1s\nKillMode=mixed\nTimeoutStopSec=5s\nSendSIGKILL=yes\nDelegate=cpu cpuset memory pids\nDelegateSubgroup=manager\nMemoryMax={}\nMemorySwapMax=0\nTasksMax={}\nOOMPolicy=continue\nLimitCORE=0\nUMask=0077\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n", plan.id, plan.id, args.join(" "), b.memory, b.tasks))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_shell_or_systemd_expansion() {
        assert_eq!(
            executable_word("/bin/wros $TOKEN %n").unwrap(),
            "\"/bin/wros $TOKEN %%n\""
        );
        assert_eq!(
            word("a $V ${V} %n \\\"b").unwrap(),
            "\"a $$V $${V} %%n \\\\\\\"b\""
        );
        for s in ["\nExecStart=/bad", "\0", "\x1b[31m", "\t"] {
            assert!(word(s).is_err());
        }
    }
    #[test]
    fn exact_future_cgroup_paths_only() {
        for path in [
            "/",
            "/sys/fs/cgroup",
            "/sys/fs/cgroup/../outside",
            "/sys/fs/cgroup//cell",
            "/sys/fs/cgroup/cell/",
            "/sys/fs/cgroup/cell/./a",
            "/tmp/cell",
        ] {
            assert!(root_path(Path::new(path)).is_err(), "{path}");
        }
        assert!(root_path(Path::new("/sys/fs/cgroup/system.slice/wros-cell.service")).is_ok());
    }
}
