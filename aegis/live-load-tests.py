#!/usr/bin/env python3
"""Isolated VM: measure synthetic audit-inbox-to-core delay under bounded bursts."""
import argparse
import json
import math
import os
import pathlib
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import audit_spool


def command(args,check=True):
    return subprocess.run(args,text=True,capture_output=True,check=check,timeout=30)


def percentiles(values):
    ordered=sorted(values)
    return {name:round(ordered[min(len(ordered)-1,math.ceil(q*len(ordered))-1)],2) if ordered else None
            for name,q in (('p50',.5),('p95',.95),('p99',.99))}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);args=parser.parse_args()
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    report={'scope':'Synthetic records submitted directly to a disposable audit inbox; not kernel loss, model latency or production SLA.',
            'rates':[],'complete':False}
    unit='aegis-load-fixture-'+str(time.time_ns())[-10:]
    with os.fdopen(fd,'w') as output:
        try:
            with tempfile.TemporaryDirectory(prefix='aegis-load-fixture-',dir='/var/lib') as directory:
                root=pathlib.Path(directory);code=root/'code';data=root/'data';runtime=root/'run';ai=root/'ai';audit=root/'audit'
                shutil.copytree(pathlib.Path(__file__).resolve().parent,code,ignore=shutil.ignore_patterns('__pycache__','assets'))
                for path in (data,runtime,ai,audit):path.mkdir(mode=0o700)
                config={'response_mode':'observe','data_dir':str(data),'runtime_dir':str(runtime),'audit_spool_dir':str(audit),
                        'ai_results_dir':str(ai),'application_enabled':False,'system_logs_enabled':False,
                        'journal_comms':[],'journal_units':[],'journal_identifiers':[]}
                config_path=root/'config.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
                boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();spool=audit_spool.Spool(config)
                try:
                    command(['systemd-run','--quiet','--unit='+unit,'--property=ProtectSystem=strict',
                             '--property=PrivateTmp=yes','--property=ProtectHome=yes','--property=ReadWritePaths='+str(root),
                             '--property=MemoryMax=256M','--property=CPUAccounting=yes','--property=MemoryAccounting=yes',
                             sys.executable,str(code/'agent.py'),'core','--config',str(config_path)])
                    deadline=time.monotonic()+30
                    while time.monotonic()<deadline and not (data/'incidents.db').exists():time.sleep(.1)
                    if not (data/'incidents.db').exists():raise RuntimeError('Collector did not initialize')
                    def resources():
                        lines=command(['systemctl','show',unit,'-p','MemoryCurrent','-p','CPUUsageNSec']).stdout.splitlines()
                        values=dict(line.split('=',1) for line in lines if '=' in line)
                        return {key:int(value) for key,value in values.items() if value.isdigit()}
                    for phase,rate in enumerate((10,100,500)):
                        before=resources();submitted={};seen={};dropped_before=spool.health()['dropped'];start=time.monotonic();wall=time.time()
                        def poll():
                            try:
                                with sqlite3.connect(data/'incidents.db',timeout=2) as db:
                                    rows=db.execute("SELECT subject FROM correlation_events WHERE kind='process_exec' AND event_time>=?",(wall-1,)).fetchall()
                                current=time.monotonic()
                                for (subject,) in rows:
                                    if subject in submitted and subject not in seen:seen[subject]=(current-submitted[subject])*1000
                            except sqlite3.Error:pass
                        for tick in range(20):
                            target=start+tick*.2
                            if target>time.monotonic():time.sleep(target-time.monotonic())
                            entries=[];pending=[]
                            for n in range(rate//5):
                                index=tick*(rate//5)+n;pid=str(300000+phase*10000+index);stamp=time.time();submitted_at=time.monotonic()
                                line=f'type=SYSCALL msg=audit({stamp:.6f}:{1000000+phase*10000+index}): success=yes pid={pid} ppid=1 uid=0 auid=1000 ses=4 exe="/usr/bin/true" key="lab_root_exec"'
                                entries.append((line,boot,{}));pending.append((pid,submitted_at))
                            accepted=spool.append_batch(entries)
                            for (pid,stamp),ok in zip(pending,accepted):
                                if ok:submitted[pid]=stamp
                            poll()
                        sent_at=time.monotonic();deadline=sent_at+60
                        while len(seen)<len(submitted) and time.monotonic()<deadline:
                            poll();time.sleep(.1)
                        health=spool.health();after=resources();elapsed=time.monotonic()-start
                        cpu=round((after['CPUUsageNSec']-before['CPUUsageNSec'])/1e9/max(.001,elapsed)*100,2) if 'CPUUsageNSec' in before and 'CPUUsageNSec' in after else None
                        report['rates'].append({'target_records_per_second':rate,'accepted':len(submitted),'observed':len(seen),
                            'actual_submission_rate':round(len(submitted)/max(.001,sent_at-start),2),
                            'dropped':health['dropped']-dropped_before,'remaining_inbox':health['rows'],
                            'observed_latency_ms':percentiles(list(seen.values())),
                            'latency_note':'Upper bounds include polling, scheduled every 100–200 ms plus query time.',
                            'cpu_percent_of_one_core':cpu,'memory_current_bytes':after.get('MemoryCurrent')})
                        print(json.dumps(report['rates'][-1]),flush=True)
                        if len(seen)!=len(submitted):raise RuntimeError('Accepted records did not all reach the core in time')
                    report['complete']=True
                finally:
                    command(['systemctl','stop',unit],False);command(['systemctl','reset-failed',unit],False);spool.db.close()
        finally:
            json.dump(report,output,indent=2);output.flush();os.fsync(output.fileno())
    print('LOAD_TEST_COMPLETE',flush=True)


if __name__=='__main__':main()
