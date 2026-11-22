#!/usr/bin/env python3
"""Isolated VM: real systemd collector processes durable batches and resumes."""
import json
import os
import pathlib
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import agent
import audit_spool


def command(args,check=True):
    return subprocess.run(args,text=True,capture_output=True,check=check,timeout=30)


def check(name,condition,**details):
    print(json.dumps({'test':name,'passed':bool(condition),**details}),flush=True)
    if not condition:raise AssertionError(name)


def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':
        raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    unit='aegis-core-fixture-'+str(time.time_ns())[-10:]
    with tempfile.TemporaryDirectory(prefix='aegis-core-fixture-',dir='/var/lib') as directory:
        root=pathlib.Path(directory);code=root/'code';data=root/'data';runtime=root/'run';ai=root/'ai';audit=root/'audit'
        shutil.copytree(pathlib.Path(agent.__file__).resolve().parent,code,ignore=shutil.ignore_patterns('__pycache__','assets'))
        for path in (data,runtime,ai,audit):path.mkdir(mode=0o700)
        config={'response_mode':'observe','data_dir':str(data),'runtime_dir':str(runtime),
                'audit_spool_dir':str(audit),'ai_results_dir':str(ai),'application_enabled':False,
                'system_logs_enabled':False,'journal_comms':[],'journal_units':[],'journal_identifiers':[]}
        config_path=root/'config.json';config_path.write_text(json.dumps(config));config_path.chmod(0o600)
        boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();now=time.time()
        spool=audit_spool.Spool(config)
        lines=[(f'type=SYSCALL msg=audit({now:.6f}:{n}): success=yes pid={900000+n} ppid=1 uid=0 auid=1000 ses=4 exe="/usr/bin/true" key="lab_root_exec"',boot,{}) for n in range(1000)]
        try:
            check('all_fixture_records_enter_durable_spool',all(spool.append_batch(lines)) and spool.health()['rows']==1000)
            cmd=['systemd-run','--quiet','--unit='+unit,'--property=ProtectSystem=strict',
                 '--property=PrivateTmp=yes','--property=ProtectHome=yes',
                 '--property=ReadWritePaths='+str(root),'--property=MemoryMax=256M',
                 sys.executable,str(code/'agent.py'),'core','--config',str(config_path)]
            command(cmd)
            def collected():
                try:
                    with sqlite3.connect(data/'incidents.db',timeout=2) as db:
                        return db.execute("SELECT count(*) FROM correlation_events WHERE kind='process_exec'").fetchone()[0]
                except sqlite3.Error:return 0
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                if collected()==1000 and spool.health()['rows']==0:break
                time.sleep(.3)
            check('real_collector_processes_all_batches',collected()==1000 and spool.health()['rows']==0,
                  collected=collected(),remaining=spool.health()['rows'])
            command(['systemctl','restart',unit])
            deadline=time.monotonic()+30;heartbeat=None
            while time.monotonic()<deadline:
                try:
                    pid=int(command(['systemctl','show',unit,'--property=MainPID','--value']).stdout)
                    with sqlite3.connect(data/'incidents.db',timeout=2) as db:
                        row=db.execute("SELECT value FROM state WHERE key='heartbeat'").fetchone()
                    heartbeat=json.loads(row[0]) if row else None
                    if pid and heartbeat and heartbeat.get('pid')==pid:break
                except (sqlite3.Error,ValueError):pass
                time.sleep(.3)
            check('collector_recovers_after_restart',bool(heartbeat) and heartbeat.get('pid')==pid)
            check('restart_does_not_duplicate_durable_records',collected()==1000 and spool.health()['rows']==0)
        finally:
            command(['systemctl','stop',unit],False)
            command(['systemctl','reset-failed',unit],False)
            spool.db.close()
    print('CORE_BATCH_VM_TESTS_PASSED',flush=True)


if __name__=='__main__':main()
