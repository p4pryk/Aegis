#!/usr/bin/env python3
"""Isolated VM: lost executor reply, durable receipt and safe file reconciliation."""
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

import agent
import persistence
import response
from rollback import Journal


def check(name,condition):
    print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)


def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':
        raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    suffix=str(time.time_ns())[-10:];path=pathlib.Path('/etc/cron.d/lab_aegis_rc'+suffix)
    content=b'# inert AEGIS recovery fixture\n';digest=hashlib.sha256(content).hexdigest()
    backup=persistence.QUARANTINE/(path.name+'.'+digest);executor=None;store=None
    try:
        with path.open('xb') as stream:stream.write(content)
        path.chmod(0o644)
        with tempfile.TemporaryDirectory(prefix='aegis-bound-recovery-') as directory:
            root=pathlib.Path(directory);runtime=root/'run';runtime.mkdir()
            config_path=root/'config.json'
            config_path.write_text(json.dumps({'response_mode':'enforce','lab_response_enabled':True,
                'data_dir':str(root),'runtime_dir':str(runtime),'executor_socket':str(runtime/'executor.sock')}))
            c=agent.load_config(config_path);store=agent.Store(c);engine=agent.CorrelatedEngine(c,store,None)
            executor=subprocess.Popen([sys.executable,str(pathlib.Path(agent.__file__)),'executor','--config',str(config_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(100):
                if pathlib.Path(c['executor_socket']).exists():break
                if executor.poll() is not None:raise RuntimeError('Executor stopped during startup')
                time.sleep(.05)
            now=time.time();sid='a'*32;ip='198.51.100.42';boot=engine.boot_id
            login=engine.normalize('app_login',ip,{'bypass':True,'success':True,'session':sid,'ip':ip,'event_id':'fixture-login'},'fixture-login',now-3)
            mutation=engine.normalize('persistence_change',str(path),{'operation':'CREATE','boot_id':boot,'pid':123,'start_ticks':321,'uid':'0','cgroup':'0::/system.slice/aegis-target-broker.service','path':str(path)},'fixture-file',now-2)
            job=engine.normalize('app_persistence_job','fixture',{'session':sid,'ip':ip,'login_id':'fixture-login','boot_id':boot,'broker_pid':123,'broker_start_ticks':321,'path':str(path),'sha256':digest},'fixture-job',now-1)
            identifier=engine.create_or_append('app_sql_persistence','fixture',job,[login,mutation])
            version=store.db.execute('SELECT version FROM cases WHERE id=?',(identifier,)).fetchone()[0]
            data=engine.snapshot(identifier,'app_sql_persistence','fixture',version)
            check('fixture_creates_locally_authorized_file_action',data['allowed_actions'][0]['action']=='quarantine_persistence')
            assessment={'attack':True,'confidence':.95,'evidence_ids':data['required_evidence_ids'],'proposed_actions':data['allowed_actions']}
            store.db.execute("UPDATE cases SET evidence_json=?,analysis_json=?,status='recognized' WHERE id=?",(json.dumps(data),json.dumps(assessment),identifier))
            response.prepare(engine,identifier,data)
            store.db.execute("UPDATE response_steps SET status='running',attempts=1 WHERE case_id=? AND position=0",(identifier,));store.db.commit()
            envelope={'case_id':identifier,'position':0,'version':version}
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as client:
                client.settimeout(5);client.connect(c['executor_socket']);client.send(json.dumps(envelope).encode())
                # Close before reading the response to reproduce a lost reply.
            journal=Journal(c);deadline=time.monotonic()+15;receipt=None
            while time.monotonic()<deadline:
                rows=journal.entries()
                receipt=next((r for r in rows if r.get('context')==envelope and r.get('state')=='contained'),None)
                if receipt:break
                time.sleep(.05)
            check('action_completed_before_reply_was_recorded',bool(receipt) and not path.exists() and backup.exists())
            result=agent.request_executor(c,envelope)
            check('retry_reconciles_original_receipt_without_second_action',result.get('reconciled') is True and result.get('undo_receipt')==receipt['id'] and len(journal.entries())==1)
            saved=dict(receipt);uncertain=dict(receipt,state='prepared');uncertain.pop('result',None);journal.save(uncertain)
            try:
                try:agent.request_executor(c,envelope);accepted=True
                except RuntimeError:accepted=False
                check('uncertain_outcome_is_not_reexecuted',not accepted and not path.exists() and backup.exists())
            finally:journal.save(saved)
            plan=journal.plan(receipt['id']);journal.apply(receipt['id'],plan['confirmation'],'Controlled recovery fixture')
            check('rollback_restores_exact_file',path.read_bytes()==content)
            try:agent.request_executor(c,envelope);accepted=True
            except RuntimeError:accepted=False
            check('restored_receipt_cannot_trigger_duplicate_containment',not accepted and path.read_bytes()==content)
            store.db.close();store=None
    finally:
        if store:store.db.close()
        if executor:executor.terminate();executor.wait(timeout=10)
        path.unlink(missing_ok=True);backup.unlink(missing_ok=True)


if __name__=='__main__':main()
