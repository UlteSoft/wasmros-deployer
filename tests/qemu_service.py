#!/usr/bin/python3
"""Run the actual systemd manager in a disposable, offline, bounded Linux guest.

Uses the hashed filesystem from qemu_supervisor.py, a newly built deployer, and
the host's installed systemd binaries plus their shared-library dependencies.
No host service is started or installed. All output belongs under .tmp.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from qemu_supervisor import build_review_terminal, digest, pack
from vendor_qualification import cgroup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'deployer', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    group = cgroup()
    args.output = args.output.resolve()
    assert '.tmp' in args.output.parts
    args.output.mkdir(parents=True, exist_ok=False)
    baseline = json.loads((args.baseline/'results.json').read_text())
    assert baseline['complete']
    root = args.output/'root'
    shutil.copytree(args.baseline/'root', root, symlinks=True)
    inputs = {}
    def copy(source, target):
        source = Path(source).resolve()
        destination = root/target.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
        inputs[str(source)] = digest(source)
    def binary(source, target):
        copy(source, target)
        run = subprocess.run(['/usr/bin/ldd', str(source)], capture_output=True, text=True, check=True, timeout=10)
        for lib in re.findall(r'(?:=>\s*)?(/[^\s]+)\s+\(', run.stdout):
            copy(lib, lib)
    binary(args.deployer, '/bin/wros-deployer')
    for source in ('/usr/lib/systemd/systemd', '/usr/lib/systemd/systemd-executor', '/usr/lib/systemd/systemd-shutdown',
                   '/usr/lib/systemd/systemd-journald', '/usr/bin/systemctl', '/usr/bin/journalctl'):
        binary(source, source)
    source = Path(__file__).resolve().parent
    inputs[str(Path(__file__).resolve())] = digest(Path(__file__).resolve())
    copy(source/'qemu_service_init.sh', '/init')
    copy(source/'qemu_service_guest.sh', '/service-test.sh')
    terminal_source = build_review_terminal(root)
    inputs[str(terminal_source)] = digest(terminal_source)
    for name in ('run', 'etc/systemd/system', 'var/log/journal', 'var/lib/systemd'):
        (root/name).mkdir(parents=True, exist_ok=True)
    (root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\nsystemd-journal:x:190:190:journal:/:/bin/false\n')
    (root/'etc/group').write_text('root:x:0:\nnobody:x:65534:\nsystemd-journal:x:190:\n')
    (root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
    (root/'etc/machine-id').write_text('87fd122ce5e94c19bde3238548ec32ee\n')
    (root/'etc/os-release').write_text('ID=wros-test\nPRETTY_NAME="Disposable WROS kernel fixture"\n')
    units = root/'etc/systemd/system'
    for name in ('basic', 'sysinit', 'local-fs', 'sockets', 'timers', 'paths', 'shutdown', 'multi-user'):
        (units/(name+'.target')).write_text('[Unit]\nDescription=Minimal test target\nDefaultDependencies=no\n')
    for name in ('systemd-journald.service', 'systemd-journald.socket', 'systemd-journald-dev-log.socket'):
        copy('/usr/lib/systemd/system/'+name, '/etc/systemd/system/'+name)
        (units/name).chmod(0o644)
    (units/'wros-test.target').write_text('[Unit]\nRequires=wros-test.service\nAfter=wros-test.service\nDefaultDependencies=no\n')
    (units/'wros-test.service').write_text('[Unit]\nRequires=systemd-journald.service\nAfter=systemd-journald.service\nDefaultDependencies=no\n[Service]\nType=oneshot\nExecStart=/bin/sh /service-test.sh\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=240s\n')
    for app in ('sed', 'sort', 'tr', 'sync', 'false', 'head'):
        if not (root/'bin'/app).exists(): (root/'bin'/app).symlink_to('busybox')
    # systemctl/journalctl live in /usr/bin; the old fixture used /bin only.
    for name in ('systemctl', 'journalctl'):
        (root/'bin'/name).symlink_to('/usr/bin/'+name)
    archive = args.output/'initramfs.cpio.gz'
    pack(root, archive)
    argv = list(baseline['argv'])
    argv[argv.index('-initrd')+1] = str(archive)
    argv[argv.index('-append')+1] += ' systemd.unit=wros-test.target systemd.show_status=false'
    receipt = args.output/'results.json'
    result = {'complete': False, 'scope': 'x86_64 Linux and real systemd; no physical device, no other platform supervisor qualification',
              'argv': argv, 'inputs': inputs, 'baseline_receipt_sha256': digest(args.baseline/'results.json'),
              'filesystem_sha256': digest(archive), 'events_before': (group/'memory.events').read_text()}
    receipt.write_text(json.dumps(result, indent=2))
    start = time.monotonic()
    with (args.output/'serial.log').open('wb') as log:
        run = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, timeout=260)
    text = (args.output/'serial.log').read_text(errors='replace')
    result.update(exit=run.returncode, elapsed_seconds=time.monotonic()-start,
                  cases=re.findall(r'CASE (\S+) PASS', text), events_after=(group/'memory.events').read_text(),
                  systemd=re.findall(r'SERVICE_SYSTEMD (.+)', text))
    result['complete'] = run.returncode == 0 and 'QEMU_SERVICE_PASS' in text and 'QEMU_SERVICE_FAIL' not in text and len(result['cases']) == 14
    receipt.write_text(json.dumps(result, indent=2))
    print(json.dumps({k:v for k,v in result.items() if k not in ('inputs', 'argv')}, indent=2))
    assert result['complete'], text[-12000:]


if __name__ == '__main__':
    main()
