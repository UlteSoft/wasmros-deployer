"""@file vendor_qualification.py
@brief Shared host resource gate for vendor qualification tests.
"""
from pathlib import Path


def cgroup():
    """@brief Resolve the 64 GiB zero-swap host cgroup enclosing the test."""
    relative = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                     if line.startswith("0::")), None)
    if relative is not None:
        root = Path("/sys/fs/cgroup")
        member = root / relative.lstrip("/")
        for path in (member, *member.parents):
            if not path.is_relative_to(root):
                break
            memory = path / "memory.max"
            if memory.is_file() and memory.read_text().strip() == "68719476736":
                if (path / "memory.swap.max").read_text().strip() == "0":
                    return path
    raise ValueError("run inside a 64 GiB cgroup with zero swap")
