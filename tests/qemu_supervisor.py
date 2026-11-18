#!/usr/bin/env python3
"""Build a disposable initramfs and qualify supervision under a real Linux kernel.

All guests have bounded RAM, two virtual CPUs, no network, no disk and no host
passthrough. Run this harness through the existing 64 GiB cgroup test gate.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time


def digest(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def pack(root,archive):
    # newc archive written as a stream; no privileged host mknod or guest tools.
    with gzip.open(archive,'wb',compresslevel=1) as out:
        inode=0
        def entry(name,mode,size,stream=None,link=None,major=0,minor=0):
            nonlocal inode
            inode+=1;name=name.encode()+b'\0'
            fields=[inode,mode,0,0,1,0,size,0,0,major,minor,len(name),0]
            out.write(b'070701'+b''.join(f'{x:08x}'.encode() for x in fields)+name)
            out.write(b'\0'*((-110-len(name))%4))
            if stream:shutil.copyfileobj(stream,out,1024*1024)
            if link:out.write(link)
            out.write(b'\0'*((-size)%4))
        for path in [root,*sorted(root.rglob('*'))]:
            name='.' if path==root else str(path.relative_to(root))
            info=path.lstat()
            if path.is_symlink():
                link=os.readlink(path).encode();entry(name,info.st_mode,len(link),link=link)
            elif path.is_dir():entry(name,stat.S_IFDIR|0o755,0)
            else:
                with path.open('rb') as f:entry(name,stat.S_IFREG|stat.S_IMODE(info.st_mode),info.st_size,stream=f)
        entry('dev/console',stat.S_IFCHR|0o600,0,major=5,minor=1)
        entry('dev/null',stat.S_IFCHR|0o666,0,major=1,minor=3)
        entry('TRAILER!!!',0,0)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("kernel","qemu","deployer","vm","cosign","admission-fixture","sdk-module","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument('--bios',type=Path,required=True)
    p.add_argument('--firmware-directory',type=Path,required=True)
    args=p.parse_args()
    group=Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip()=='0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip()=='68719476736'
    assert (group/'memory.swap.max').read_text().strip()=='0'
    args.output=args.output.resolve()
    assert '.tmp' in args.output.parts
    args.output.mkdir(parents=True,exist_ok=False)
    root=args.output/'root';root.mkdir()
    for name in ('bin','proc','sys','dev','tmp','run','bundle','trust','state','scratch'):(root/name).mkdir()
    def copy(source,target,mode=0o755):
        target=root/target.lstrip('/');target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target);target.chmod(mode)
    def binary(source,target):
        copy(source,target)
        result=subprocess.run(['/usr/bin/ldd',str(source)],capture_output=True,text=True,timeout=10)
        assert result.returncode==0 or 'not a dynamic executable' in result.stderr+result.stdout
        for lib in re.findall(r'(?:=>\s*)?(/[^\s]+)\s+\(',result.stdout):
            copy(lib,lib)
    source=Path(__file__).resolve().parent
    peer=args.output/'supervisor-peer'
    compile_argv=['/usr/bin/cc','-O3','-g','-Wall','-Wextra','-Werror',str(source/'supervisor_peer.c'),'-o',str(peer)]
    subprocess.run(compile_argv,check=True,timeout=60)
    for path,target in ((Path('/bin/busybox'),'/bin/busybox'),(Path('/usr/bin/strace'),'/bin/strace'),(args.deployer,'/bin/wros-deployer'),
                        (args.vm,'/bin/uwvm2-ros'),(args.cosign,'/bin/cosign'),(peer,'/bin/supervisor-peer')):
        binary(path.resolve(),target)
    for app in ('sh','mount','mkdir','chmod','chown','sha256sum','grep','cat','cut','sleep','poweroff','rmdir','wc','tail','awk','cp','dd','ln','rm'):
        (root/'bin'/app).symlink_to('busybox')
    copy(source/'qemu_supervisor_guest.sh','/init')
    for name in ('body.wasm','unsigned.wasm'):
        copy(args.admission_fixture/'bundle'/name,'/bundle/'+name,0o644)
    copy(args.sdk_module,'/bundle/sdk.wasm',0o644)
    (root/'bundle/loop.wasm').write_bytes(bytes.fromhex('0061736d0100000001040160000003020100070a01065f737461727400000a0901070003400c000b0b'))
    policy=(args.admission_fixture/'policies/body.policy').read_text()
    trust=next(line.split('=',1)[1] for line in policy.splitlines() if line.startswith('trust_root='))
    copy(trust,'/trust/root.pem',0o644)
    copy(Path(trust).parent/'signer.pem','/trust/signer.pem',0o644)
    archive=args.output/'initramfs.cpio.gz'
    pack(root,archive)
    argv=[str(args.qemu),'-nodefaults','-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','2,sockets=2,cores=1,threads=1','-m','4096',
          '-object','memory-backend-ram,id=mem0,size=2G','-object','memory-backend-ram,id=mem1,size=2G',
          '-numa','node,nodeid=0,cpus=0,memdev=mem0','-numa','node,nodeid=1,cpus=1,memdev=mem1',
          '-display','none','-serial','stdio','-monitor','none','-nic','none','-no-reboot','-bios',str(args.bios),'-L',str(args.firmware_directory),
          '-kernel',str(args.kernel),'-initrd',str(archive),'-append',
          'console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all']
    result={'complete':False,'scope':'x86_64 disposable kernel, no physical robot or systemd recovery qualification',
            'argv':argv,'compile':compile_argv,'inputs':{str(path.resolve()):digest(path) for path in [args.kernel,args.bios,args.deployer,args.vm,args.cosign,args.sdk_module,source/'qemu_supervisor_guest.sh',source/'supervisor_peer.c',Path(__file__)]}}
    receipt=args.output/'results.json';receipt.write_text(json.dumps(result,indent=2))
    start=time.monotonic()
    with (args.output/'serial.log').open('wb') as log:
        run=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=240)
    text=(args.output/'serial.log').read_text(errors='replace')
    result.update(exit=run.returncode,elapsed_seconds=time.monotonic()-start,cases=re.findall(r'CASE (\S+) PASS',text))
    result['complete']=run.returncode==0 and 'QEMU_SUPERVISOR_PASS' in text and 'QEMU_SUPERVISOR_FAIL' not in text and len(result['cases'])==37
    receipt.write_text(json.dumps(result,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k not in ('argv','inputs','compile')},indent=2))
    assert result['complete'],text[-10000:]


if __name__=='__main__':main()
