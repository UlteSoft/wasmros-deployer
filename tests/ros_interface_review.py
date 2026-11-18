"""Compile a strict C guest that exercises every reviewed ROSv2 interface decision."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('sdk', 'runtime', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--toolchain', type=Path, help='Override the installed site toolchain together with --sysroots')
    parser.add_argument('--sysroots', type=Path)
    args = parser.parse_args()
    if bool(args.toolchain) != bool(args.sysroots):
        parser.error('supply both --toolchain and --sysroots for an explicit qualified build')
    group = Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    if (Path('/proc/self/cgroup').read_text().strip() != '0::/'+str(group.relative_to('/sys/fs/cgroup'))
            or (group/'memory.max').read_text().strip() != '68719476736'
            or (group/'memory.swap.max').read_text().strip() != '0'):
        parser.error('expected the existing 64 GiB qualification cgroup')
    root = Path(__file__).resolve().parents[1]
    out = args.output.resolve()
    if not out.is_relative_to(root/'.tmp'):
        parser.error('choose a fresh output directory in the deployer .tmp')
    sdk = args.sdk.resolve()
    catalog = root/'protocol/ros-interfaces.txt'
    schemas = json.loads((sdk/'share/abi/ros.json').read_text())
    ops = schemas['operations']
    expected = [op['name'] for op in ops]
    if (schemas['module'] != 'uwvm_ros_v2' or 'abi' not in expected
            or len(set(expected)) != len(expected) or sorted(expected) != catalog.read_text().splitlines()):
        raise ValueError('the installed SDK and deployer have different ROSv2 interfaces')
    out.mkdir(parents=True, exist_ok=False)
    xml = ET.Element('recommendations')
    lines = ['#include <wros/scene.h>', 'void _start(void) {']
    for op in ops:
        name = op['name']
        if not re.fullmatch(r'[a-z][a-z0-9_.]*', name):
            raise ValueError('invalid SDK interface name')
        granted = name == 'abi'
        ET.SubElement(xml, 'interface', name=name, expose='allow' if granted else 'deny')
        params = op['wasm_signature']['parameters']
        expression = 'wr_' + name.replace('.','_') + '(' + ', '.join('0' for _ in params) + ')'
        lines.append(f'    if ({expression} != {2 if granted else 13}) __builtin_trap();')
    lines.append('}')
    source, wasm, policy = out/'catalog.c', out/'catalog.wasm', out/'permissions.xml'
    source.write_text('\n'.join(lines)+'\n')
    ET.indent(xml, space='  ')
    policy.write_bytes(ET.tostring(xml, encoding='utf-8')+b'\n')
    selection = [] if args.toolchain is None else [
        '--toolchain', str(args.toolchain.resolve()), '--sysroots', str(args.sysroots.resolve())]
    command = [str(sdk/'bin/wrc'), *selection, '--target', 'wasm32', '-O3', '-g', '--reactor',
               '--export', '_start', '--build-receipt', str(source), '-o', str(wasm)]
    subprocess.run(command, cwd=out, check=True, timeout=180)
    receipt = Path(str(wasm)+'.wros-build.json')
    build = json.loads(receipt.read_bytes())
    if build['mode'] != 'strict' or build['vm_sha256'] != digest(args.runtime):
        raise ValueError('strict SDK release and selected VM differ')
    subprocess.run([sys.executable,'-B',sdk/'install/qualification.py','--artifact',wasm,'--receipt',receipt,
                    '--vm',args.runtime.resolve(),'--approved-receipt-sha256',digest(receipt)],check=True,timeout=180)
    sys.path.insert(0, str(sdk/'install'))
    from imports import inspect
    actual = inspect(wasm.read_bytes())
    observed = {row['name']:(row['params'],row['results']) for row in actual}
    signatures = {op['name']:(op['wasm_signature']['parameters'],op['wasm_signature']['results']) for op in ops}
    if observed != signatures or len(actual) != len(ops) or any(
            row['module'] != schemas['module'] or row['kind'] != 0 for row in actual):
        raise ValueError('compiled guest imports differ from the exact SDK signatures')
    report = dict(complete=True, vm=digest(args.runtime), wasm=digest(wasm), catalog=digest(catalog),
                  reviewed=len(ops), sdk_abi=digest(sdk/'share/abi/ros.json'), guest_source=digest(source),
                  permissions=digest(policy), build_receipt=digest(receipt), compiler_argv=command)
    (out/'results.json').write_text(json.dumps(report, indent=2)+'\n')


if __name__ == '__main__':
    main()
