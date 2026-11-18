#!/usr/bin/env python3
"""One-time key/channel setup: matched Rust/OpenSSL native reference and HW profiles.

This is NOT per-message latency. Both endpoints, four retained descriptors,
reciprocal keys, seals and credential-enabled carriers are created and closed.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
from pathlib import Path
import statistics
import subprocess
import sys
import time


def sha(path):
    with Path(path).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('vm-source','openssl','rust-artifacts','reference-context','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',action='store_true')
    a=p.parse_args()
    for k,v in vars(a).items():
        if isinstance(v,Path):setattr(a,k,v.resolve())
    root=Path(__file__).resolve().parents[1]
    group=Path('/sys/fs/cgroup/system.slice/docker-af71cb24aa7993383f76ad9c06750b17eb66fd090a2c9ba64b544b19cda9c913.scope')
    assert Path('/proc/self/cgroup').read_text().strip()=='0::/'+str(group.relative_to('/sys/fs/cgroup'))
    assert (group/'memory.max').read_text().strip()=='68719476736' and (group/'memory.swap.max').read_text().strip()=='0'
    assert '.tmp' in a.output.parts;a.output.mkdir(parents=True,exist_ok=False)
    libs=list(a.rust_artifacts.glob('libwros_deployer-*.rlib'));assert len(libs)==1
    dependency=json.loads((a.openssl/'receipt.json').read_text())
    sys.path.insert(0,str(a.vm_source/'tools/ros_scene'))
    from performance_build_policy import compile_policy
    dependency_policy=compile_policy(dependency['identity']['spec']['cflags'])
    assert all(sha(a.openssl/k)==v for k,v in dependency['artifacts'].items())
    paths=[*sorted((root/'src').glob('*.rs')),root/'Cargo.toml',root/'Cargo.lock',root/'tests/support/attachment_benchmark.rs',
           a.vm_source/'test/0084.ros-runtime/provider_bootstrap_performance.cpp',
           a.vm_source/'tools/ros_scene/hardware_sampling.py',a.vm_source/'tools/ros_scene/driver_attachment_microarchitecture.py',
           libs[0],a.openssl/'libcrypto.a',a.openssl/'receipt.json',a.reference_context,Path(__file__).resolve()]
    report=dict(complete=False,scope=__doc__,dependency_build_policy=dependency_policy,inputs={str(f):sha(f) for f in paths},commands=[],trials=[],profiles=[],events_before=(group/'memory.events').read_text())
    receipt=a.output/'results.json'
    def save():receipt.write_text(json.dumps(report,indent=2)+'\n')
    def run(label,cmd):
        cmd=list(map(str,cmd));start=time.monotonic()
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
        (a.output/(label+'.stdout')).write_text(r.stdout);(a.output/(label+'.stderr')).write_text(r.stderr)
        report['commands'].append(dict(label=label,argv=cmd,exit=r.returncode,seconds=time.monotonic()-start));save()
        assert r.returncode==0,(label,r.stderr[-2000:]);print(label,'passed',flush=True);return r.stdout
    run('rust-build',['/opt/rust/1.98.0/bin/rustc','--edition=2021','-C','opt-level=3','-C','debuginfo=2','-C','overflow-checks=yes',
        '-L','dependency='+str(a.rust_artifacts),'--extern','wros_deployer='+str(libs[0]),root/'tests/support/attachment_benchmark.rs','-o',a.output/'rust-setup'])
    run('native-build',['/usr/bin/clang++-22','-std=c++23','-O3','-g','-UNDEBUG','-Wall','-Wextra','-Werror','-I'+str(a.openssl/'include'),
        a.vm_source/'test/0084.ros-runtime/provider_bootstrap_performance.cpp',a.openssl/'libcrypto.a','-ldl','-pthread','-o',a.output/'native-setup'])
    report['artifacts']={str(a.output/(kind+'-setup')):sha(a.output/(kind+'-setup')) for kind in ('rust','native')};save()
    def trial(stdout):return json.loads(next(x for x in stdout.splitlines() if x.startswith('{"pairs":')))
    for i in range(7):
        for kind in (('native','rust') if i%2==0 else ('rust','native')):
            row=trial(run(f'{i}-{kind}',['/usr/bin/taskset','-c','4',a.output/(kind+'-setup'),'10000']));row.update(kind=kind,round=i);report['trials'].append(row)
    report['median_ns']={kind:statistics.median(x['ns_per_pair'] for x in report['trials'] if x['kind']==kind) for kind in ('native','rust')}
    report['ratio']=report['median_ns']['rust']/report['median_ns']['native'];save()
    if a.profile:
        sys.path.insert(0,str(a.vm_source/'tools/ros_scene'))
        from hardware_sampling import audit_samples,reference_frequency,vtune_periods
        from driver_attachment_microarchitecture import sample_statistics
        def mapped(path,source=None):
            with path.open() as stream:
                rows=csv.DictReader((line for line in stream if not line.startswith('war:')),delimiter='\t')
                return sum(1 for row in rows if row.get('Source Line','').isdigit() and int(row['Source Line'])>0
                    and (source in row.get('Source File','') if source else row.get('Address','').startswith('0x'))
                    and any(float(v or 0)>0 for k,v in row.items() if k and k.startswith('Hardware Event Count:')))
        vtune='/opt/intel/oneapi/vtune/latest/bin64/vtune'
        hz=reference_frequency(a.reference_context,platform.node())
        events={'CPU_CLK_UNHALTED.REF_TSC':('umask=0x3',24000),'INST_RETIRED.ANY':('event=0xc0',240000)}
        config=','.join(f'cpu_core/{encoding},period={period},name={name}/u' for name,(encoding,period) in events.items())
        for kind in ('native','rust'):
            for analysis in ('hardware','microarchitecture'):
                label=kind+'-'+analysis;target=a.output/label;exe=a.output/(kind+'-setup')
                if analysis=='hardware':
                    trace=a.output/(kind+'.perf')
                    stdout=run(label+'-collect',['/usr/bin/perf','record','-o',trace,'-N','-B','-T','--sample-cpu','-e',config,'--','/usr/bin/taskset','-c','4',exe,'30000'])
                    pid=trial(stdout)['pid'];attrs=run(label+'-attributes',['/usr/bin/perf','evlist','-v','-i',trace])
                    samples=run(label+'-samples',['/usr/bin/perf','script','--ns','-F','comm,pid,tid,time,event,period,ip','-i',trace])
                    raw=run(label+'-raw',['/usr/bin/perf','script','-D','-i',trace])
                    selected='\n'.join(line for line in samples.splitlines() if len(line.split(maxsplit=2))==3 and line.split()[0]==exe.name[:15] and line.split()[1].partition('/')[0]==str(pid))+'\n'
                    audit=audit_samples(attrs,selected,raw,{k:v[1] for k,v in events.items()},hz,target_comm=exe.name[:15])
                    run(label+'-import',[vtune,'-import',trace,'-result-dir',target,'-source-search-dir',root,'-source-search-dir',a.vm_source,'-finalization-mode','full'])
                else:
                    stdout=run(label+'-collect',[vtune,'-collect','uarch-exploration','-knob','pmu-collection-mode=detailed','-knob','dram-bandwidth-limits=false','-knob','sampling-interval=1',
                        '-no-analyze-system','-no-summary','-data-limit=400','-return-app-exitcode','-result-dir',target,'-source-search-dir',root,'-source-search-dir',a.vm_source,
                        '--','/usr/bin/taskset','-c','4',exe,'30000'])
                    pid=trial(stdout)['pid'];audit=vtune_periods(target)
                filters=['-filter','process-id='+str(pid)]
                for suffix,by in [('functions','function'),('source','function,source-file,source-line')]:
                    run(label+'-'+suffix,[vtune,'-report','hw-events','-result-dir',target,*filters,'-group-by',by,'-format','csv','-csv-delimiter','tab','-report-output',a.output/(label+'-'+suffix+'.tsv')])
                rows=list(csv.reader((a.output/(label+'-functions.tsv')).read_text().splitlines(),delimiter='\t'))
                patterns=('provision',) if kind=='native' else ('attachment::endpoints','10attachment9endpoints')
                function=next(row[0] for row in rows if row and any(pattern in row[0] for pattern in patterns))
                asm=a.output/(label+'-assembly.tsv')
                run(label+'-assembly',[vtune,'-report','hw-events','-result-dir',target,*filters,'-source-object','function='+function,'-group-by','address','-column','Assembly,Source Line,Hardware Event Count','-format','csv','-csv-delimiter','tab','-report-output',asm])
                source_count=mapped(a.output/(label+'-source.tsv'),'provider_bootstrap_performance.cpp' if kind=='native' else 'attachment.rs')
                assembly_count=mapped(asm)
                row=dict(kind=kind,analysis=analysis,pid=pid,audit=audit,function=function,source_mapping=source_count>0,assembly_mapping=assembly_count>0,sampled_source_rows=source_count,sampled_assembly_rows=assembly_count)
                if analysis=='microarchitecture':
                    summary=a.output/(label+'-summary.tsv')
                    run(label+'-summary',[vtune,'-report','summary','-result-dir',target,*filters,'-format','csv','-report-output',summary])
                    row['topdown_summary']=all(x in summary.read_text() for x in ('Retiring','Front-End Bound','Bad Speculation','Back-End Bound'))
                    stats=sample_statistics(run(label+'-stats',['/usr/bin/perf','report','--stdio','--stats','--percent-limit','100','-i',target/'data.0/system-wide.perf']))
                    row['sample_statistics']=stats;row['loss_and_throttle_free']=not any(stats.get(k,0) for k in ('LOST','LOST_SAMPLES','THROTTLE','UNTHROTTLE'))
                report['profiles'].append(row);save()
    report['inputs_unchanged']=all(sha(k)==v for k,v in {**report['inputs'],**report['artifacts']}.items())
    report['events_after']=(group/'memory.events').read_text()
    report['complete']=report['inputs_unchanged'] and (not a.profile or len(report['profiles'])==4 and all(r['source_mapping'] and r['assembly_mapping'] and (r['audit']['ten_us_reference_period_verified'] if r['analysis']=='hardware' else r['topdown_summary'] and r['loss_and_throttle_free']) for r in report['profiles']))
    save();assert report['complete']


if __name__=='__main__':main()
