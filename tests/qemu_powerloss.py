#!/usr/bin/env python3
"""Three disposable kernel boots with an abrupt QEMU death and a private disk.

Use a completed qemu_supervisor.py output as --baseline and supply the matching
Debian installer kernel-image and ext4-module udebs. Only selected regular kernel
modules are copied into the test image; nothing is loaded into the host kernel.
No physical disk, network, shared directory or passthrough is attached.
"""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import time
from qemu_supervisor import pack, digest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('baseline','kernel-package','ext4-package','storage-package','output'):
        p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();a.output=a.output.resolve()
    assert '.tmp' in a.output.parts
    group=Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip()=='0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip()=='68719476736' and (group/'memory.swap.max').read_text().strip()=='0'
    baseline=json.loads((a.baseline/'results.json').read_text());assert baseline['complete']
    a.output.mkdir(exist_ok=False)
    root=a.output/'root';shutil.copytree(a.baseline/'root',root,symlinks=True)
    source=Path(__file__).with_name('qemu_powerloss_guest.sh')
    shutil.copyfile(source,root/'init');(root/'init').chmod(0o755)
    for app in ('insmod','dd','rm'):
        path=root/'bin'/app
        if not path.exists():path.symlink_to('busybox')
    # Order is explicit: prerequisites precede filesystems and block drivers.
    names=['crc16','crc32c_generic','crc32c_intel','libcrc32c','mbcache','jbd2','ext4','virtio_blk']
    modules={}
    for package in (a.kernel_package,a.ext4_package,a.storage_package):
        data=subprocess.run(['/usr/bin/dpkg-deb','--fsys-tarfile',package],capture_output=True,check=True,timeout=30).stdout
        assert len(data)<64*1048576
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
            for member in archive:
                if not member.name.endswith(('.ko','.ko.xz')):continue
                name=Path(member.name).name.removesuffix('.xz').removesuffix('.ko')
                if name not in names:continue
                assert member.isfile() and member.size<4*1048576
                payload=archive.extractfile(member).read()
                if member.name.endswith('.xz'):payload=lzma.decompress(payload)
                assert len(payload)<8*1048576 and name not in modules
                modules[name]=payload
    assert {'virtio_blk','mbcache','jbd2','ext4'}<=modules.keys(),sorted(modules)
    (root/'modules').mkdir()
    for index,name in enumerate(names):
        if name in modules:(root/'modules'/f'{index:02}-{name}.ko').write_bytes(modules[name])
    disk=a.output/'state.ext4'
    with disk.open('xb') as f:f.truncate(64*1048576)
    disk.chmod(0o600)
    subprocess.run(['/usr/sbin/mkfs.ext4','-q','-F',disk],check=True,timeout=30)
    image=a.output/'initramfs.cpio.gz';pack(root,image)
    old=baseline['argv']
    value=lambda flag:old[old.index(flag)+1]
    base=[old[0],'-nodefaults','-machine','q35','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','2048','-display','none','-serial','stdio','-monitor','none','-nic','none','-no-reboot',
          '-bios',value('-bios'),'-L',value('-L'),'-kernel',value('-kernel'),'-initrd',str(image),
          '-drive',f'file={disk},format=raw,if=none,id=state,cache=writeback','-device','virtio-blk-pci,drive=state,serial=wros-test']
    inputs=[Path(__file__).resolve(),source,Path(__file__).with_name('qemu_supervisor.py'),a.baseline/'results.json',a.kernel_package,a.ext4_package,a.storage_package,
            root/'bin/wros-deployer',root/'bin/uwvm2-ros',root/'bin/cosign',Path(value('-kernel'))]
    results={'complete':False,'scope':'x86_64 QEMU power loss, kernel boot identity, durable cold starts and ENOSPC; no physical safety or systemd claim',
             'inputs':{str(path.resolve()):digest(path) for path in inputs},'disk_bytes':disk.stat().st_size,'cases':[],
             'cgroup':str(group),'memory_events_before':(group/'memory.events').read_text()}
    receipt=a.output/'results.json'
    receipt.write_text(json.dumps(results,indent=2))
    boots=[]
    for phase in (1,2,3):
        argv=base+['-append',f'console=ttyS0 quiet panic=-1 rdinit=/init cgroup_no_v1=all wros_boot_phase={phase}']
        log=a.output/f'boot-{phase}.log';started=time.monotonic();killed=False
        with log.open('wb') as out:
            child=subprocess.Popen(argv,stdout=out,stderr=subprocess.STDOUT)
            try:
                while child.poll() is None:
                    text=log.read_text(errors='replace')
                    if phase==1 and 'QEMU_POWERLOSS_READY_TO_CUT' in text:
                        child.kill();killed=True;break
                    assert time.monotonic()-started<90,'kernel scenario timeout'
                    time.sleep(.02)
                exit_code=child.wait(timeout=10)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=10)
        text=log.read_text(errors='replace')
        found=re.search(r'BOOT_ID ([0-9a-f-]{36}) PHASE',text)
        boots.append(found[1] if found else None)
        passed='QEMU_POWERLOSS_FAIL' not in text and (killed and exit_code==-9 if phase==1 else exit_code==0 and f'QEMU_POWERLOSS_PASS_PHASE_{phase}' in text)
        results['cases'].append({'phase':phase,'argv':argv,'exit':exit_code,'abrupt_qemu_kill':killed,'boot_id':boots[-1],'pass':passed,'elapsed':time.monotonic()-started})
        receipt.write_text(json.dumps(results,indent=2))
        assert passed,text[-10000:]
        print('power-loss phase',phase,'passed',flush=True)
    results['complete']=None not in boots and len(set(boots))==3 and 'CASE_DURABLE_STORAGE_FULL_PASS' in text and all(digest(Path(p))==h for p,h in results['inputs'].items())
    results['memory_events_after']=(group/'memory.events').read_text()
    results['disk_final_sha256']=digest(disk)
    receipt.write_text(json.dumps(results,indent=2));assert results['complete']


if __name__=='__main__':main()
