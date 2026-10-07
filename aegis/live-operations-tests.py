#!/usr/bin/env python3
"""Isolated VM acceptance: real audit downtime/load and a slow fixture response.
The slow response uses a fixture executor; live attack suites test actual defense.
"""
import json
import os
import pathlib
import pwd
import sqlite3
import subprocess
import tempfile
import time

import agent
import audit_spool
import maintenance
import response

RESULTS=[]
DB='/var/lib/defense-agent/incidents.db'

def check(name,condition,**details):
    item=dict(test=name,passed=bool(condition),**details);RESULTS.append(item);print(json.dumps(item),flush=True)
    if not condition:raise AssertionError(name)


def command(args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=20)


def wait(fn,seconds=40):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        value=fn()
        if value:return value
        time.sleep(.1)
    raise TimeoutError('Condition not reached')


def query(sql,args=()):
    with sqlite3.connect(DB,timeout=10) as db:return db.execute(sql,args).fetchall()


def main():
    if os.geteuid()!=0:raise SystemExit('Run as root on the isolated training VM')
    suffix=str(time.time_ns())[-10:];user='lab_spool_'+suffix;created=False
    config=agent.load_config();spool=audit_spool.Spool(config)
    try:
        command(['systemctl','stop','defense-agent'])
        command(['useradd','-M','-s','/bin/bash',user]);created=True
        uid=pwd.getpwnam(user).pw_uid
        wait(lambda:spool.db.execute('SELECT count(*) FROM inbox WHERE line LIKE ? OR line LIKE ?',('%acct="'+user+'"%','%adding user id='+str(uid)+' %')).fetchone()[0])
        check('real_account_event_durable_while_core_stopped',spool.health()['rows']>0)
        command(['systemctl','start','defense-agent'])
        count=lambda:query("SELECT count(*) FROM observations WHERE kind='account_created' AND subject=?",(user,))[0][0]
        wait(count)
        check('real_account_event_replayed_after_restart',count()==1)
        command(['systemctl','restart','defense-agent']);time.sleep(1)
        check('restart_does_not_duplicate_committed_account',count()==1)
        before=spool.health();lost_before=int(command(['auditctl','-s']).stdout.split('lost ')[1].split()[0])
        started=time.time();pids=[]
        for _ in range(200):
            process=subprocess.Popen(['/usr/bin/true']);pids.append(str(process.pid));process.wait(timeout=5)
        def observed():
            rows=query("SELECT subject FROM correlation_events WHERE kind='process_exec' AND event_time>=?",(started-1,))
            return len(set(pids)&{r[0] for r in rows})
        # Kernel audit timestamps have millisecond precision; include the boundary
        # millisecond, then match exact PIDs rather than treating time as identity.
        try:wait(lambda:observed()==len(pids),60)
        except TimeoutError:
            check('real_200_process_burst_observed',False,observed=observed(),expected=len(pids))
        after=spool.health();lost_after=int(command(['auditctl','-s']).stdout.split('lost ')[1].split()[0])
        check('real_200_process_burst_observed',observed()==200,seconds=round(time.time()-started,3))
        check('burst_did_not_increase_spool_or_kernel_loss',after['dropped']==before['dropped'] and lost_after==lost_before)
    finally:
        command(['systemctl','start','defense-agent']);spool.db.close()
        if created:command(['userdel',user])

    with tempfile.TemporaryDirectory(prefix='aegis-operations-') as directory:
        root=pathlib.Path(directory);(root/'ai').mkdir()
        config=dict(agent.DEFAULTS,data_dir=directory,audit_spool_dir=str(root/'audit'),ai_results_dir=str(root/'ai'),application_log=str(root/'app'))
        store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
        event=engine.normalize('fixture','response',{},'slow-response-fixture',time.time())
        identifier=engine.create_or_append('fixture','response',event)
        data={'events':[event],'allowed_actions':[{'action':'block_ip','ip':'198.51.100.10'}]}
        store.db.execute('UPDATE cases SET evidence_json=?,analysis_json=? WHERE id=?',(json.dumps(data),'{"summary":"Authorized slow-executor fixture"}',identifier))
        response.prepare(engine,identifier,data);engine.status(identifier,'recognized');store.db.close()
        pid=os.fork()
        if pid==0:
            try:
                child_store=agent.Store(config)
                def slow_executor(_):
                    (root/'executing').touch();time.sleep(15);return {'verified':True}
                child=agent.CorrelatedEngine(config,child_store,slow_executor);response.resume(child,time.time());os._exit(0)
            except BaseException:os._exit(1)
        try:
            wait(lambda:(root/'executing').exists())
            store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None);spool=audit_spool.Spool(config)
            start=time.monotonic()
            spool.append_batch([(f'type=SYSCALL msg=audit({time.time()}:{n}): success=yes pid={900000+n} ppid=1 uid=0 auid=1000 ses=4 exe="/usr/bin/true" key="lab_root_exec"',engine.boot_id,{}) for n in range(100)])
            audit_spool.consume(engine,spool)
            duration=time.monotonic()-start
            check('core_ingests_100_records_while_response_is_waiting',store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0]==100 and not os.waitpid(pid,os.WNOHANG)[0],seconds=round(duration,3))
            _,status=os.waitpid(pid,0);pid=None
            check('separate_response_worker_completes',os.waitstatus_to_exitcode(status)==0 and store.db.execute('SELECT status FROM cases WHERE id=?',(identifier,)).fetchone()[0]=='defended')
            output=root/'case-export.json';maintenance.export_case(store.path,identifier,output)
            check('export_preserves_verified_response_and_attempts',json.loads(output.read_text())['response_attempts'][0]['completed_at'] is not None and output.stat().st_mode&0o777==0o600)
            spool.db.close();store.db.close()
        finally:
            if pid:
                try:os.kill(pid,9);os.waitpid(pid,0)
                except ProcessLookupError:pass


if __name__=='__main__':
    try:main()
    finally:pathlib.Path('/tmp/aegis-operations-results.json').write_text(json.dumps(RESULTS,indent=2))
