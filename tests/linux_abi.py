#!/usr/bin/env python3
"""Cross-build and execute Rust contract tests for the five Linux ABIs.

This checks userspace ABI behavior. Namespace/cgroup supervision additionally
requires a full-kernel fixture; qemu-user is not a replacement for that test.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for option in ('rust','components','sysroots','clang','qemu-bin','output'):
        parser.add_argument('--'+option,type=Path,required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    group=Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip()=='0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip()=='68719476736'
    assert (group/'memory.swap.max').read_text().strip()=='0'
    args.output=args.output.resolve();assert '.tmp' in args.output.parts
    args.output.mkdir(parents=True,exist_ok=False)
    (args.output/'test-data').mkdir()
    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream,'sha256').hexdigest()
    inputs=[*sorted((root/'src').glob('*.rs')),root/'tests/configuration.rs',
            root/'Cargo.toml',root/'Cargo.lock',root/'.cargo/config.toml',
            root/'protocol/ros-interfaces.txt',Path(__file__).resolve()]
    results={'complete':False,'scope':'five Linux userspace ABIs; privileged supervision requires full-kernel qualification',
             'inputs':{str(path):digest(path) for path in inputs},
             'cgroup':str(group),'events_before':(group/'memory.events').read_text(),'cases':[]}
    receipt=args.output/'results.json'
    def execute(label,argv,env=None):
        run=subprocess.run(list(map(str,argv)),cwd=root,env=env,capture_output=True,text=True,timeout=120)
        (args.output/(label+'.stdout')).write_text(run.stdout)
        (args.output/(label+'.stderr')).write_text(run.stderr)
        results['cases'].append({'label':label,'argv':list(map(str,argv)),'exit':run.returncode})
        receipt.write_text(json.dumps(results,indent=2))
        assert run.returncode==0,(label,run.stderr[-4000:],run.stdout[-1000:])
        print(label,'passed',flush=True)
        return run.stdout
    version=execute('rustc-version',[args.rust/'bin/rustc','--version','--verbose'])
    release=next(line.split(': ',1)[1] for line in version.splitlines() if line.startswith('release:'))
    cases=[('x86_64','x86_64-unknown-linux-gnu','x86_64-linux-gnu',None),
           ('i686','i686-unknown-linux-gnu','i686-linux-gnu','native-i686'),
           ('aarch64','aarch64-unknown-linux-gnu','aarch64-linux-gnu','qemu-aarch64'),
           ('armhf','armv7-unknown-linux-gnueabihf','arm-linux-gnueabihf','qemu-arm'),
           ('arm','arm-unknown-linux-gnueabi','arm-linux-gnueabi','qemu-arm')]
    for abi,target,gnu,emulator in cases:
        env=dict(os.environ,PATH=str(args.rust/'bin')+':/usr/bin:/bin',CARGO_HOME=str(root/'.tmp/cargo'),CARGO_TARGET_DIR=str(args.output/'target'),WROS_TEST_DIRECTORY=str(args.output/'test-data'))
        flags=[]
        if emulator:
            component=(args.components/f'rust-std-{release}-{target}'/f'rust-std-{target}').resolve()
            sysroot=(args.sysroots/abi).resolve()
            assert (component/'lib/rustlib'/target/'lib').is_dir()
            versions=[path for path in (sysroot/'usr/lib/gcc'/gnu).iterdir() if path.name.isdigit() and path.is_dir()]
            assert len(versions)==1,'provide a sysroot with one pinned GCC runtime version'
            gcc=versions[0]
            flags=['--sysroot='+str(component),'-C','linker='+str(args.clang.resolve()),
                   '-C','link-arg=--target='+gnu,'-C','link-arg=--sysroot='+str(sysroot),
                   '-C','link-arg=--gcc-install-dir='+str(gcc),'-C','link-arg=-fuse-ld=lld']
        env['CARGO_ENCODED_RUSTFLAGS']='\x1f'.join(flags)
        raw=execute(abi+'-compile',[args.rust/'bin/cargo','test','--release','--locked','--offline','--target',target,'--no-run','--message-format=json'],env)
        executables=[]
        for line in raw.splitlines():
            item=json.loads(line)
            if item.get('reason')=='compiler-artifact' and item.get('executable') and item.get('profile',{}).get('test'):
                executables.append(Path(item['executable']))
        assert len(executables)==3
        for index,exe in enumerate(executables):
            with exe.open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
            run=[exe,'--test-threads=1']
            if emulator=='native-i686':
                run=[sysroot/'lib/ld-linux.so.2','--library-path',str(sysroot/'lib/i386-linux-gnu')+':'+str(sysroot/'usr/lib/i386-linux-gnu'),*run]
            elif emulator:run=[args.qemu_bin/emulator,'-L',sysroot,*run]
            execute(abi+'-tests-'+str(index),run,env)
            results['cases'][-1]['executable_sha256']=sha
    results['inputs_unchanged']=all(digest(Path(path))==value for path,value in results['inputs'].items())
    results['events_after']=(group/'memory.events').read_text()
    results['complete']=results['inputs_unchanged'];receipt.write_text(json.dumps(results,indent=2))
    assert results['complete'],'source changed during ABI qualification'


if __name__=='__main__':main()
