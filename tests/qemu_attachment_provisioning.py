#!/usr/bin/env python3
"""Qualify Rust-provisioned encrypted attachments across isolated guest identities.

Offline x86_64 QEMU, 4 GiB RAM, no disks, shared folders or device passthrough.
The manager, VM and receiver have separate nested cgroups. This is a test
provisioner and harmless query peer, not production native-driver orchestration.
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
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('kernel','qemu','bios','firmware-directory','provisioner','peer','vm','module','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--receiver-checks',type=Path,help='Also run the 19 native receiver boundary cases in the guest')
    a=p.parse_args()
    group=Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip()=='0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip()=='68719476736' and (group/'memory.swap.max').read_text().strip()=='0'
    a.output=a.output.resolve();assert '.tmp' in a.output.parts;a.output.mkdir(parents=True,exist_ok=False)
    root=a.output/'root'
    for name in ('bin','proc','sys','dev','tmp','run'):(root/name).mkdir(parents=True)
    inputs={}
    def binary(path,target):
        path=path.resolve();inputs[str(path)]=digest(path)
        dst=root/target.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,dst);dst.chmod(0o755)
        run=subprocess.run(['/usr/bin/ldd',str(path)],capture_output=True,text=True,timeout=15)
        assert run.returncode==0 or 'not a dynamic executable' in run.stdout+run.stderr
        for lib in re.findall(r'(?:=>\s*)?(/[^\s]+)\s+\(',run.stdout):
            dst=root/lib.lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(lib,dst);dst.chmod(0o755);inputs[lib]=digest(Path(lib))
    for src,dst in [(Path('/bin/busybox'),'/bin/busybox'),(a.provisioner,'/bin/provisioner'),(a.peer,'/bin/provider'),(a.vm,'/bin/uwvm2-ros')]:binary(src,dst)
    if a.receiver_checks:binary(a.receiver_checks,'/bin/receiver-checks')
    for name in ('sh','mount','mkdir','poweroff','cat','sleep','rmdir'):(root/'bin'/name).symlink_to('busybox')
    shutil.copyfile(a.module,root/'body.wasm');(root/'body.wasm').chmod(0o444);inputs[str(a.module.resolve())]=digest(a.module)
    modes=['success','wrong-key','wrong-binding','wrong-descriptor','bad-profile','bad-ready','peer-exit','unexpected-rights','bad-origin']
    init='''#!/bin/sh
export PATH=/bin
fail() { echo QEMU_ATTACHMENT_FAIL; poweroff -f; exit 1; }
mount -t proc proc /proc || fail
mount -t sysfs sysfs /sys || fail
mount -t devtmpfs devtmpfs /dev || fail
mount -t cgroup2 cgroup2 /sys/fs/cgroup || fail
mkdir /sys/fs/cgroup/manager /sys/fs/cgroup/attachments || fail
echo $$ > /sys/fs/cgroup/manager/cgroup.procs || fail
echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control || fail
echo 536870912 > /sys/fs/cgroup/manager/memory.max || fail
echo 0 > /sys/fs/cgroup/manager/memory.swap.max || fail
echo 32 > /sys/fs/cgroup/manager/pids.max || fail
echo 2147483648 > /sys/fs/cgroup/attachments/memory.max || fail
echo 0 > /sys/fs/cgroup/attachments/memory.swap.max || fail
echo 64 > /sys/fs/cgroup/attachments/pids.max || fail
echo '+cpu +memory +pids' > /sys/fs/cgroup/attachments/cgroup.subtree_control || fail
export WROS_TEST_CHILD_CGROUP_ROOT=/sys/fs/cgroup/attachments
'''
    create='''for name in vm provider; do
 mkdir /sys/fs/cgroup/attachments/$name || fail
 echo 1073741824 > /sys/fs/cgroup/attachments/$name/memory.max || fail
 echo 0 > /sys/fs/cgroup/attachments/$name/memory.swap.max || fail
 echo 16 > /sys/fs/cgroup/attachments/$name/pids.max || fail
 echo '100000 100000' > /sys/fs/cgroup/attachments/$name/cpu.max || fail
done
'''
    cleanup='''for name in vm provider; do
 test -z "$(cat /sys/fs/cgroup/attachments/$name/cgroup.procs)" || fail
 cat /sys/fs/cgroup/attachments/$name/memory.events
 rmdir /sys/fs/cgroup/attachments/$name || fail
done
'''
    if a.receiver_checks:init+='/bin/receiver-checks || fail\n'
    # Each mode gets fresh groups: immutable device BPF rules persist after a
    # provisioner exits and must never be replaced on an existing group.
    for mode in modes:
        init+=create+f'/bin/provisioner /bin/uwvm2-ros /bin/provider /body.wasm {mode} || fail\n'+cleanup
    init+='''echo QEMU_ATTACHMENT_PASS
poweroff -f
'''
    (root/'init').write_text(init);(root/'init').chmod(0o755)
    archive=a.output/'initramfs.cpio.gz';pack(root,archive)
    argv=list(map(str,[a.qemu,'-nodefaults','-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-display','none','-serial','stdio','-monitor','none','-nic','none','-no-reboot','-bios',a.bios,'-L',a.firmware_directory,'-kernel',a.kernel,'-initrd',archive,'-append','console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all']))
    inputs.update({str(f.resolve()):digest(f) for f in (a.kernel,a.bios,Path(__file__))})
    result=dict(complete=False,scope=__doc__,argv=argv,inputs=inputs,init=init,initramfs_sha256=digest(archive),events_before=(group/'memory.events').read_text())
    receipt=a.output/'results.json';receipt.write_text(json.dumps(result,indent=2))
    start=time.monotonic()
    with (a.output/'serial.log').open('wb') as log:run=subprocess.run(argv,stdout=log,stderr=subprocess.STDOUT,timeout=180)
    text=(a.output/'serial.log').read_text(errors='replace')
    result.update(exit=run.returncode,seconds=time.monotonic()-start,cases=re.findall(r'CASE (\S+) PASS',text),events_after=(group/'memory.events').read_text(),inputs_unchanged=all(digest(Path(k))==v for k,v in inputs.items()))
    result['receiver_boundary_checks']=bool(a.receiver_checks)
    result['kernel_device_filter_for_both_peers']=all(text.splitlines().count('TEST_DEVICE_FILTER_INSTALLED '+peer)==len(modes) for peer in ('vm','provider'))
    result['complete']=run.returncode==0 and 'QEMU_ATTACHMENT_PASS' in text and 'QEMU_ATTACHMENT_FAIL' not in text and len(result['cases'])==len(modes)+(19 if a.receiver_checks else 0) and result['inputs_unchanged'] and result['kernel_device_filter_for_both_peers'] and not re.search(r'oom(?:_kill|_group_kill)? [1-9]',text)
    receipt.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ('inputs','argv','init')},indent=2));assert result['complete'],text[-5000:]


if __name__=='__main__':main()
