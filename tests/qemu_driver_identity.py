#!/usr/bin/env python3
"""Qualify distinct-UID local IPC in a disposable Linux kernel, never on the host.

The baseline peer is compiled from the published pre-fix VM headers. The new
peer exercises clock evidence and, optionally, the actual newly compiled VM.
This test provisioner does not qualify native provider execution by the deployer.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from qemu_supervisor import digest, pack


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel', 'qemu', 'bios', 'firmware-directory', 'baseline-peer', 'peer', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    p.add_argument('--vm', type=Path)
    p.add_argument('--module', type=Path)
    args = p.parse_args()
    assert bool(args.vm) == bool(args.module)
    group = Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip() == '0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip() == '68719476736'
    assert (group/'memory.swap.max').read_text().strip() == '0'
    args.output = args.output.resolve()
    assert '.tmp' in args.output.parts
    args.output.mkdir(parents=True, exist_ok=False)
    root = args.output/'root'
    for name in ('bin', 'proc', 'sys', 'dev', 'tmp'):
        (root/name).mkdir(parents=True)
    inputs = {}

    def binary(path, target):
        path = path.resolve()
        inputs[str(path)] = digest(path)
        dest = root/target.lstrip('/')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, dest)
        dest.chmod(0o755)
        run = subprocess.run(['/usr/bin/ldd', str(path)], capture_output=True, text=True, timeout=15)
        assert run.returncode == 0 or 'not a dynamic executable' in run.stdout+run.stderr
        for lib in re.findall(r'(?:=>\s*)?(/[^\s]+)\s+\(', run.stdout):
            dest = root/lib.lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(lib, dest)
            dest.chmod(0o755)
            inputs[lib] = digest(Path(lib))

    for source, target in ((Path('/bin/busybox'), '/bin/busybox'),
                           (args.baseline_peer, '/bin/baseline'), (args.peer, '/bin/peer')):
        binary(source, target)
    for name in ('sh', 'mount', 'mkdir', 'poweroff'):
        (root/'bin'/name).symlink_to('busybox')
    extra = ''
    if args.vm:
        binary(args.vm, '/bin/uwvm2-ros')
        shutil.copyfile(args.module, root/'body.wasm')
        (root/'body.wasm').chmod(0o444)
        inputs[str(args.module.resolve())] = digest(args.module)
        extra = '/bin/peer /bin/uwvm2-ros /body.wasm || fail\n'
    init = '''#!/bin/sh
export PATH=/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
fail() { echo QEMU_DRIVER_IDENTITY_FAIL; poweroff -f; }
/bin/baseline || fail
/bin/peer || fail
'''+extra+'''echo QEMU_DRIVER_IDENTITY_PASS
poweroff -f
'''
    (root/'init').write_text(init)
    (root/'init').chmod(0o755)
    archive = args.output/'initramfs.cpio.gz'
    pack(root, archive)
    argv = [str(args.qemu), '-nodefaults', '-machine', 'q35', '-accel', 'tcg,thread=multi',
            '-cpu', 'max', '-smp', '2', '-m', '4096', '-display', 'none', '-serial', 'stdio',
            '-monitor', 'none', '-nic', 'none', '-no-reboot', '-bios', str(args.bios),
            '-L', str(args.firmware_directory), '-kernel', str(args.kernel), '-initrd', str(archive),
            '-append', 'console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all']
    inputs.update({str(f.resolve()): digest(f) for f in [args.kernel, args.bios, Path(__file__)]})
    result = dict(complete=False, scope='x86_64 full-kernel clock/credential isolation; test provisioner only',
                  argv=argv, inputs=inputs, init=init, initramfs_sha256=digest(archive),
                  events_before=(group/'memory.events').read_text())
    receipt = args.output/'results.json'
    receipt.write_text(json.dumps(result, indent=2))
    start = time.monotonic()
    with (args.output/'serial.log').open('wb') as log:
        run = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=180)
    text = (args.output/'serial.log').read_text(errors='replace')
    result.update(exit=run.returncode, elapsed_seconds=time.monotonic()-start,
                  cases=re.findall(r'CASE (\S+) PASS', text), events_after=(group/'memory.events').read_text(),
                  inputs_unchanged=all(digest(Path(k)) == v for k, v in inputs.items()))
    result['complete'] = (run.returncode == 0 and 'QEMU_DRIVER_IDENTITY_PASS' in text
                          and 'QEMU_DRIVER_IDENTITY_FAIL' not in text
                          and len(result['cases']) == (9 if args.vm else 8) and result['inputs_unchanged'])
    receipt.write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k not in ('argv', 'inputs', 'init')}, indent=2))
    assert result['complete'], text[-5000:]


if __name__ == '__main__':
    main()
