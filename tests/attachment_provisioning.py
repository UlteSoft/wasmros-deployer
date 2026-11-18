#!/usr/bin/env python3
"""Real VM / Rust provisioner / separate C++ receiver, serial 64 GiB qualification.

The receiver implements one harmless parameter query. This qualifies bootstrap
and encrypted IPC interoperability, not vendor lifecycle or hardware authority.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('vm', 'vm-source', 'openssl', 'output'):
        p.add_argument('--'+name, type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    group = Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip() == '0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip() == '68719476736'
    assert (group/'memory.swap.max').read_text().strip() == '0'
    args.output = args.output.resolve()
    args.vm = args.vm.resolve(); args.vm_source = args.vm_source.resolve(); args.openssl = args.openssl.resolve()
    sys.path.insert(0, str(args.vm_source/'tools/ros_scene'))
    from performance_build_policy import compile_policy, vm_policy, openssl_policy
    build_policy = dict(vm=vm_policy(args.vm), openssl=openssl_policy([
        str(args.openssl/'libssl.a'), str(args.openssl/'libcrypto.a')]))
    assert '.tmp' in args.output.parts
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'test-data').mkdir()
    paths = [*sorted((root/'src').glob('*.rs')), root/'Cargo.toml', root/'Cargo.lock', root/'.cargo/config.toml',
             root/'tests/support/attachment_provisioner.rs', root/'tests/configuration.rs', Path(__file__), args.vm,
             args.openssl/'receipt.json', args.openssl/'libssl.a', args.openssl/'libcrypto.a',
             args.vm_source/'tools/ros_scene/performance_build_policy.py',
             args.vm_source/'test/0084.ros-runtime/provider_bootstrap.cpp',
             *sorted((args.vm_source/'src/uwvm2/imported/ros/scene').glob('*.h'))]
    results = dict(complete=False, scope=__doc__, inputs={str(p): digest(p) for p in paths},
                   build_policy=build_policy, events_before=(group/'memory.events').read_text(), runs=[])
    receipt = args.output/'results.json'
    def save(): receipt.write_text(json.dumps(results, indent=2)+'\n')
    def run(label, argv, env=None, timeout=120):
        start = time.monotonic()
        with (args.output/(label+'.stdout')).open('wb') as out, (args.output/(label+'.stderr')).open('wb') as err:
            r = subprocess.run(list(map(str, argv)), cwd=root, env=env, stdout=out, stderr=err, timeout=timeout)
        results['runs'].append(dict(label=label, argv=list(map(str, argv)), exit=r.returncode, seconds=time.monotonic()-start))
        save(); assert r.returncode == 0, (label, (args.output/(label+'.stderr')).read_text()[-4000:])
        print(label, 'passed', flush=True)
    save()
    env = dict(os.environ, PATH='/opt/rust/1.98.0/bin:/usr/bin:/bin', CARGO_BUILD_JOBS='1',
               CARGO_HOME=str(root/'.tmp/cargo'), CARGO_TARGET_DIR=str(args.output/'target'),
               WROS_TEST_DIRECTORY=str(args.output/'test-data'))
    run('rust-tests', ['/opt/rust/1.98.0/bin/cargo', 'test', '--release', '--locked', '--offline', '--', '--test-threads=1'], env)
    run('rust-provisioner', ['/opt/rust/1.98.0/bin/cargo', 'build', '--example', 'attachment-provisioner', '--release', '--locked', '--offline'], env)
    peer = args.output/'provider'
    command = ['/usr/bin/clang++-22', '-std=c++23', '-O3', '-g', '-UNDEBUG', '-Wall', '-Wextra', '-Werror', '-pthread',
               '-DUWVM_ROS_ATTACHMENT_OPENSSL', '-I'+str(args.openssl/'include'), '-I'+str(args.vm_source/'src'),
               '-I'+str(args.vm_source/'third-parties/fast_io/include'), args.vm_source/'test/0084.ros-runtime/provider_bootstrap.cpp',
               args.openssl/'libssl.a', args.openssl/'libcrypto.a', '-ldl', '-pthread', '-o', peer]
    results['build_policy']['receiver'] = compile_policy(command)
    run('receiver-build', command)
    run('receiver-decoder', [peer])
    sys.path.insert(0, str(args.vm_source/'test/0084.ros-runtime'))
    sys.path.insert(0, str(args.vm_source/'tools/ros_scene'))
    spec = importlib.util.spec_from_file_location('driver_performance', args.vm_source/'tools/ros_scene/driver_attachment_performance.py')
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    provisioner = args.output/'target/release/examples/attachment-provisioner'
    for mode in ('success', 'wrong-key', 'wrong-binding', 'wrong-descriptor', 'bad-profile', 'bad-ready', 'peer-exit', 'unexpected-rights', 'bad-origin'):
        wat = args.output/(mode+'.wat'); wasm = wat.with_suffix('.wasm')
        wat.write_text(helper.fixture(1, time.monotonic_ns()+120_000_000_000).render())
        run(mode+'-module', ['/usr/bin/wat2wasm', '--enable-multi-memory', '--debug-names', wat, '-o', wasm])
        run(mode, [provisioner, args.vm, peer, wasm, mode], timeout=30)
    results['artifacts'] = {str(path): digest(path) for path in (provisioner, peer)}
    results['inputs_unchanged'] = all(digest(path) == value for path,value in results['inputs'].items())
    results['events_after'] = (group/'memory.events').read_text()
    results['complete'] = results['inputs_unchanged']; save(); assert results['complete']


if __name__ == '__main__': main()
