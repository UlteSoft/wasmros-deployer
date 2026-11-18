#!/usr/bin/env python3
"""Build and execute the external bootstrap decoder or receiver on five Linux ABIs."""
import argparse
import hashlib
import json
from pathlib import Path
import resource
import subprocess
import time


def sha(p):
    with Path(p).open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('vm-source','tls-receipt','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--suite',choices=('decoder','receiver'),default='decoder')
    a=p.parse_args();a.vm_source=a.vm_source.resolve();a.output=a.output.resolve()
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    group=Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip()=='0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip()=='68719476736' and (group/'memory.swap.max').read_text().strip()=='0'
    assert '.tmp' in a.output.parts;a.output.mkdir(parents=True,exist_ok=False)
    prior=json.loads(a.tls_receipt.read_text());assert prior['complete']
    source='provider_bootstrap_receiver.cpp' if a.suite=='receiver' else 'provider_bootstrap.cpp'
    paths=[a.tls_receipt.resolve(),Path(__file__).resolve(),a.vm_source/'test/0084.ros-runtime'/source,
           *sorted((a.vm_source/'src/uwvm2/imported/ros/scene').glob('*.h'))]
    result=dict(complete=False,suite=a.suite,inputs={str(f):sha(f) for f in paths},events_before=(group/'memory.events').read_text(),runs=[])
    receipt=a.output/'results.json'
    def save():receipt.write_text(json.dumps(result,indent=2)+'\n')
    def run(abi,action,cmd):
        start=time.monotonic()
        with (a.output/(abi+'-'+action+'.log')).open('wb') as log:r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,timeout=120)
        result['runs'].append(dict(abi=abi,action=action,argv=cmd,exit=r.returncode,seconds=time.monotonic()-start));save()
        assert r.returncode==0,(abi,action);print(abi,action,'passed',flush=True)
    for abi in ('x86_64','i686','aarch64','armhf','arm'):
        compile=next(x['argv'] for x in prior['runs'] if x['abi']==abi and x['action']=='compile')
        execute=next(x['argv'] for x in prior['runs'] if x['abi']==abi and x['action']=='run')
        previous=Path(next(x for x in compile if x.endswith('/test/0084.ros-runtime/attachment_tls.cpp'))).parents[2]
        binary=compile[compile.index('-o')+1];new=str(a.output/abi)
        command=[x.replace(str(previous),str(a.vm_source)).replace('/test/0084.ros-runtime/attachment_tls.cpp','/test/0084.ros-runtime/'+source) for x in compile]
        command[command.index('-o')+1]=new
        run(abi,'compile',command);run(abi,'run',[new if x==binary else x for x in execute])
        result['runs'][-1]['binary_sha256']=sha(new)
        if abi=='x86_64':native=command
    sanitized=native.copy();sanitized[sanitized.index('-o')+1]=str(a.output/'sanitized')
    sanitized+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    run('sanitized','compile',sanitized);run('sanitized','run',[str(a.output/'sanitized')])
    result['inputs_unchanged']=all(sha(k)==v for k,v in result['inputs'].items())
    result['events_after']=(group/'memory.events').read_text();result['complete']=result['inputs_unchanged'];save();assert result['complete']


if __name__=='__main__':main()
