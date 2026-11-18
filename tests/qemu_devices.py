#!/usr/bin/env python3
"""Test actual cgroup device BPF and ownership in an offline disposable kernel.

No host mount, mknod, BPF attachment, device passthrough or privileged command.
The guest has 2 GiB RAM, two virtual CPUs, no disk and no network.
"""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from qemu_supervisor import digest, pack


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel', 'qemu', 'bios', 'firmware-directory', 'checks', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    group = Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip() == '0::/' + str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip() == '68719476736'
    assert (group/'memory.swap.max').read_text().strip() == '0'
    a.output = a.output.resolve(); assert '.tmp' in a.output.parts
    a.output.mkdir(parents=True, exist_ok=False)
    root = a.output/'root'
    for name in ('bin', 'proc', 'sys', 'dev', 'tmp', 'run'):
        (root/name).mkdir(parents=True)
    inputs = {}
    def binary(path, target):
        path = path.resolve(); inputs[str(path)] = digest(path)
        dst = root/target.lstrip('/'); dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dst); dst.chmod(0o755)
        run = subprocess.run(['/usr/bin/ldd', str(path)], capture_output=True, text=True, timeout=15)
        assert run.returncode == 0 or 'not a dynamic executable' in run.stdout+run.stderr
        for lib in re.findall(r'(?:=>\s*)?(/[^\s]+)\s+\(', run.stdout):
            dst = root/lib.lstrip('/'); dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(lib, dst); dst.chmod(0o755); inputs[lib] = digest(Path(lib))
    binary(Path('/bin/busybox'), '/bin/busybox'); binary(a.checks, '/bin/checks')
    for name in ('sh', 'mount', 'mkdir', 'poweroff', 'cat'):
        (root/'bin'/name).symlink_to('busybox')
    init = '''#!/bin/sh
export PATH=/bin
fail() { echo QEMU_DEVICES_FAIL; poweroff -f; exit 1; }
mount -t proc proc /proc || fail
mount -t sysfs sysfs /sys || fail
mount -t devtmpfs devtmpfs /dev || fail
mount -t cgroup2 cgroup2 /sys/fs/cgroup || fail
echo offline-qemu-no-hardware > /run/device-fixture-marker
export WROS_DISPOSABLE_DEVICE_GUEST=yes
/bin/checks || fail
echo QEMU_DEVICES_PASS
poweroff -f
'''
    (root/'init').write_text(init); (root/'init').chmod(0o755)
    archive = a.output/'initramfs.cpio.gz'; pack(root, archive)
    argv = list(map(str, [a.qemu, '-nodefaults', '-machine', 'q35', '-accel', 'tcg,thread=multi', '-cpu', 'max', '-smp', '2', '-m', '2048', '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-nic', 'none', '-no-reboot', '-bios', a.bios, '-L', a.firmware_directory, '-kernel', a.kernel, '-initrd', archive, '-append', 'console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all']))
    sources = [*Path('src').glob('*.rs'), Path('Cargo.toml'), Path('Cargo.lock'), Path('tests/support/device_kernel_checks.rs'), Path('tests/qemu_supervisor.py'), Path(__file__)]
    inputs.update({str(f.resolve()): digest(f) for f in [a.kernel, a.bios, *sources]})
    result = dict(complete=False, scope=__doc__, argv=argv, inputs=inputs, init=init, initramfs_sha256=digest(archive), events_before=(group/'memory.events').read_text())
    receipt = a.output/'results.json'; receipt.write_text(json.dumps(result, indent=2))
    start = time.monotonic()
    with (a.output/'serial.log').open('wb') as log:
        run = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=120)
    text = (a.output/'serial.log').read_text(errors='replace')
    result.update(exit=run.returncode, seconds=time.monotonic()-start, cases=re.findall(r'CASE (\S+) PASS', text), events_after=(group/'memory.events').read_text(), inputs_unchanged=all(digest(Path(k)) == v for k, v in inputs.items()))
    result['complete'] = run.returncode == 0 and 'QEMU_DEVICES_PASS' in text and 'QEMU_DEVICES_FAIL' not in text and len(result['cases']) == 21 and result['inputs_unchanged']
    receipt.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('inputs','argv','init')}, indent=2))
    assert result['complete'], text[-7000:]


if __name__ == '__main__':
    main()
