"""Shared cgroup and project scratch checks for host qualification tests."""
import os
from pathlib import Path


def cgroup():
    """Require a 64 GiB limit and disabled swap on the test and its parent."""
    base = Path("/sys/fs/cgroup")
    relative = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                     if line.startswith("0::/")), None)
    if relative:
        leaf = (base / relative.lstrip("/")).resolve()
        if leaf.is_relative_to(base) and leaf.parent != base and leaf != base:
            for group in (leaf, leaf.parent):
                if ((group / "memory.max").read_text().strip() != "68719476736"
                        or (group / "memory.swap.max").read_text().strip() != "0"):
                    break
            else:
                return leaf
    raise ValueError("the test cgroup and its parent must each have 64 GiB and zero swap")


def qualification_environment(*destinations, vm_source=None):
    """Validate all temporary paths before creating artifacts or launching tools."""
    group = cgroup()
    deployer = Path(__file__).resolve().parents[1]
    vm = Path(vm_source).resolve() if vm_source else deployer.parent / "uwvm2-ros"
    projects = (deployer, vm, vm.parent / "uwvm2-ros-sdk-v2")
    tmp = [os.environ.get(key) for key in ("TMPDIR", "TMP", "TEMP")]
    if any(not value for value in tmp):
        raise ValueError("TMPDIR, TMP and TEMP must name the same project scratch directory")
    locations = {Path(value).resolve(strict=True) for value in tmp}
    if len(locations) != 1 or not next(iter(locations)).is_dir():
        raise ValueError("TMPDIR, TMP and TEMP must name the same project scratch directory")
    for path in (*locations, *destinations):
        path = Path(path).resolve()
        nearest = next(parent for parent in (path, *path.parents) if parent.exists())
        if not any(path.is_relative_to(root / ".tmp") and nearest.stat().st_dev == root.stat().st_dev
                   for root in projects):
            raise ValueError(f"choose a path on a project disk under its .tmp directory: {path}")
    return group
