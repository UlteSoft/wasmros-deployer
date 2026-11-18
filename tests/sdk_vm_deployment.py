"""Build a site-installed SDK application and exercise a signed deployment in QEMU."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

TESTS = Path(__file__).resolve().parent


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'vm', 'vm-source', 'deployer', 'cosign', 'kernel', 'bios',
                 'firmware-directory', 'output', 'authority-directory'):
        parser.add_argument('--' + name, required=True, type=lambda value: Path(value).resolve())
    # QEMU installations can use a multi-call launcher that inspects argv[0].
    parser.add_argument('--qemu', required=True, type=lambda value: Path(value).absolute())
    parser.add_argument('--engine', choices=('aot', 'interpreter'), required=True)
    args = parser.parse_args()
    if not args.output.is_relative_to(TESTS.parent / '.tmp'):
        parser.error('choose a new results directory inside the deployer .tmp')
    if not args.authority_directory.is_relative_to(args.vm_source / '.tmp'):
        parser.error('choose a new private test authority directory inside the VM .tmp')

    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    args.authority_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = args.output / 'results.json'
    state = dict(complete=False, engine=args.engine, inputs={
        str(p): digest(p) for p in (args.vm, args.deployer, args.cosign, args.sdk / 'bin/wrc',
                                    args.sdk / 'share/abi/ros.json', args.kernel, args.bios,
                                    TESTS / 'sdk_vm_deployment.py', TESTS / 'ros_interface_review.py',
                                    TESTS / 'qemu_supervisor.py', TESTS / 'qemu_supervisor_guest.sh',
                                    TESTS / 'clock_permissions.py', TESTS / 'wsea_preflight.py')
    }, steps=[])

    def save():
        receipt.write_text(json.dumps(state, indent=2) + '\n')

    def run(label, script, arguments, timeout):
        command = list(map(str, [sys.executable, '-B', TESTS / script, *arguments]))
        log = args.output / (label + '.log')
        row = dict(name=label, argv=command, exit=None)
        state['steps'].append(row)
        save()
        with log.open('xb') as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        row.update(exit=result.returncode, logSha256=digest(log))
        save()
        result.check_returncode()

    probe = args.output / 'probe'
    admitted = args.authority_directory / 'admission'
    clocks = args.authority_directory / 'clock'
    guest = args.output / 'qemu'
    common = ['--vm', args.vm, '--cosign', args.cosign, '--deployer', args.deployer]
    run('compile', 'ros_interface_review.py', ['--sdk', args.sdk, '--runtime', args.vm, '--output', probe], 300)
    run('sign', 'wsea_preflight.py', [*common, '--vm-source', args.vm_source, '--sdk-source', args.sdk,
        '--sdk-module', probe / 'catalog.wasm', '--sdk-interface-probe', probe, '--output', admitted], 900)
    run('clock', 'clock_permissions.py', [*common, '--vm-source', args.vm_source, '--output', clocks], 900)
    run('deploy', 'qemu_supervisor.py', [*common, '--qemu', args.qemu, '--kernel', args.kernel,
        '--bios', args.bios, '--firmware-directory', args.firmware_directory, '--admission-fixture', admitted,
        '--signed-sdk-module', admitted / 'bundle/sdk.signed.wasm', '--sdk-module', probe / 'catalog.wasm',
        '--sdk-engine', args.engine, '--sdk-memory-bytes', 1536 << 20, '--clock-fixture', clocks,
        '--sdk-interface-probe', probe, '--output', guest], 1200)
    qemu = json.loads((guest / 'results.json').read_bytes())
    if not qemu['complete'] or 'signed-sdk-reviewed-every-ros-interface' not in qemu['cases']:
        raise ValueError('missing completed signed interface review')
    state.update(complete=True, cases=qemu['cases'], qemuReceiptSha256=digest(guest / 'results.json'))
    save()


if __name__ == '__main__':
    main()
