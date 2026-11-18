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
    parser.add_argument('--accelerator', choices=('tcg', 'kvm'), default='tcg',
                        help='QEMU CPU backend for the isolated x86_64 guest')
    parser.add_argument('--guest-timeout-seconds', type=int, default=240,
                        help='Bound the whole QEMU guest run to 30..1800 seconds including compiler startup')
    parser.add_argument('--aot-policy', choices=('default','fast-compile','balanced','max'))
    parser.add_argument('--engine', choices=('aot', 'interpreter'), required=True)
    parser.add_argument('--sdk-abi-application', type=lambda value: Path(value).resolve(),
                        help='Test a signed-site SDK application whose only import is uwvm_ros_v2.abi')
    parser.add_argument('--approved-build-receipt-sha256', help='Operator-approved SHA-256 of the adjacent .wros-build.json')
    args = parser.parse_args()
    if args.aot_policy and args.engine != 'aot':
        parser.error('--aot-policy requires --engine aot')
    if not 30 <= args.guest_timeout_seconds <= 1800:
        parser.error('guest time limit must be between 30 and 1800 seconds')
    if bool(args.sdk_abi_application) != bool(args.approved_build_receipt_sha256):
        parser.error('provide the SDK application and approved build receipt digest together')
    if not args.output.is_relative_to(TESTS.parent / '.tmp'):
        parser.error('choose a new results directory inside the deployer .tmp')
    if not args.authority_directory.is_relative_to(args.vm_source / '.tmp'):
        parser.error('choose a new private test authority directory inside the VM .tmp')

    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    args.authority_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = args.output / 'results.json'
    state = dict(complete=False, engine=args.engine, accelerator=args.accelerator, inputs={
        str(p): digest(p) for p in (args.vm, args.deployer, args.cosign,
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
    if args.sdk_abi_application:
        artifact = args.output / 'application.wasm'
        supplied = args.sdk_abi_application
        build_receipt = args.output / 'application.wros-build.json'
        for source, target, limit in ((supplied, artifact, 128 << 20),
                                      (Path(str(supplied)+'.wros-build.json'), build_receipt, 1 << 20)):
            with source.open('rb') as stream:
                data = stream.read(limit+1)
            if len(data) > limit:
                raise ValueError('SDK input exceeds the test fixture budget')
            target.write_bytes(data)
            state['inputs'][str(source)] = digest(target)
        if digest(build_receipt) != args.approved_build_receipt_sha256:
            raise ValueError('SDK receipt differs from the operator-approved digest')
        approved = json.loads(build_receipt.read_bytes())
        checker = args.sdk / 'install/qualification.py'
        verifier_args = []
        if approved.get('format') == 'wros-d-betterc-build-v1':
            checker = args.sdk / 'bin/wrd'
            verifier_args = ['verify']
        state['inputs'][str(checker)] = digest(checker)
        run('verify-build', checker, [*verifier_args, '--vm', args.vm, '--artifact', artifact,
            '--receipt', build_receipt, '--approved-receipt-sha256', args.approved_build_receipt_sha256], 180)
        state['language'] = approved['language']
        probe_args = []
        required_case = 'signed-sdk-verification-at-deployer-and-vm'
    else:
        state['inputs'][str(args.sdk/'bin/wrc')] = digest(args.sdk/'bin/wrc')
        run('compile', 'ros_interface_review.py', ['--sdk', args.sdk, '--runtime', args.vm, '--output', probe], 300)
        artifact = probe/'catalog.wasm'
        probe_args = ['--sdk-interface-probe',probe]
        required_case = 'signed-sdk-reviewed-every-ros-interface'
    run('sign', 'wsea_preflight.py', [*common, '--vm-source', args.vm_source, '--sdk-source', args.sdk,
        '--sdk-module', artifact, *probe_args, '--output', admitted], 900)
    run('clock', 'clock_permissions.py', [*common, '--vm-source', args.vm_source, '--output', clocks], 900)
    run('deploy', 'qemu_supervisor.py', [*common, '--accelerator', args.accelerator, '--guest-timeout-seconds', args.guest_timeout_seconds, '--qemu', args.qemu, '--kernel', args.kernel,
        '--bios', args.bios, '--firmware-directory', args.firmware_directory, '--admission-fixture', admitted,
        '--signed-sdk-module', admitted / 'bundle/sdk.signed.wasm', '--sdk-module', artifact,
        '--sdk-engine', args.engine, '--sdk-memory-bytes', 1536 << 20, '--clock-fixture', clocks,
        *probe_args, *(['--sdk-aot-policy', args.aot_policy] if args.aot_policy else []), '--output', guest], args.guest_timeout_seconds + 180)
    qemu = json.loads((guest / 'results.json').read_bytes())
    if not qemu['complete'] or required_case not in qemu['cases']:
        raise ValueError('missing signed deployment result: '+required_case)
    state.update(complete=True, cases=qemu['cases'], qemuReceiptSha256=digest(guest / 'results.json'))
    save()


if __name__ == '__main__':
    main()
