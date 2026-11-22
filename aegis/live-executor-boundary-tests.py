#!/usr/bin/env python3
"""Isolated VM: synthetic evidence, real executor, account, firewall and rollback."""
import hashlib
import json
import os
import pathlib
import pwd
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import agent
from rollback import Journal


def run(*args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=20)


def check(name, result):
    print(json.dumps({'test':name,'passed':bool(result)}), flush=True)
    if not result: raise AssertionError(name)


def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':
        raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    suffix=str(time.time_ns())[-8:]
    actor='lab_ea_'+suffix; target='lab_et_'+suffix
    namespace='aegis-boundary';host='ebveth0';peer='ebveth1';ip='10.252.89.2';gateway='10.252.89.1'
    users=[];executor=None;server=None;store=None
    try:
        for name in (actor,target):
            run('useradd','-M','-s','/bin/bash',name);users.append(name)
        actor_uid=pwd.getpwnam(actor).pw_uid
        run('ip','netns','add',namespace)
        run('ip','link','add',host,'type','veth','peer','name',peer)
        run('ip','link','set',peer,'netns',namespace)
        run('ip','addr','add',gateway+'/30','dev',host)
        run('ip','link','set',host,'up')
        run('ip','netns','exec',namespace,'ip','addr','add',ip+'/30','dev',peer)
        run('ip','netns','exec',namespace,'ip','link','set',peer,'up')
        run('ip','netns','exec',namespace,'ip','link','set','lo','up')
        server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        server.bind((gateway,18991));server.listen(10)
        probe_code='import socket; s=socket.create_connection(("10.252.89.1",18991),timeout=1); s.close()'
        def reachable():return run('ip','netns','exec',namespace,'python3','-c',probe_code,check=False).returncode==0
        check('dedicated_source_reachable_before_containment',reachable())
        with tempfile.TemporaryDirectory(prefix='aegis-boundary-') as directory:
            root=pathlib.Path(directory);config_path=root/'config.json';runtime=root/'run';runtime.mkdir()
            settings={'response_mode':'enforce','lab_response_enabled':True,'ssh_lab_users_enabled':True,
                      'ssh_response_users':[actor],'ssh_account_creator_allowlist':['root','labadmin'],
                      'ssh_dedicated_source_ips':[ip],'data_dir':str(root),'runtime_dir':str(runtime),
                      'executor_socket':str(runtime/'executor.sock'),'ai_results_dir':str(root),'block_seconds':120}
            config_path.write_text(json.dumps(settings));config=agent.load_config(config_path)
            store=agent.Store(config)
            executor=subprocess.Popen([sys.executable,str(pathlib.Path(agent.__file__)),'executor','--config',str(config_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            for _ in range(100):
                if pathlib.Path(config['executor_socket']).exists():break
                if executor.poll() is not None:raise RuntimeError('Executor stopped during startup')
                time.sleep(.05)
            try:
                agent.request_executor(config,{'action':'block_ip','ip':ip})
                raise AssertionError('Raw action unexpectedly accepted')
            except RuntimeError as exc:
                check('arbitrary_raw_action_rejected', 'committed case step' in str(exc))
            check('raw_action_does_not_block',reachable())
            engine=agent.CorrelatedEngine(config,store,lambda request:agent.request_executor(config,request))
            engine.execute_step=lambda identifier,position,version:agent.request_executor(config,{'case_id':identifier,'position':position,'version':version})
            now=time.time()
            for n in range(5):engine.failure('ssh',ip,now-.5,str(n),user=actor)
            snapshot={'pid':200,'ppid':100,'start_ticks':10,'cgroup':'/user.slice'}
            with patch.object(agent,'process_snapshot',return_value=snapshot):
                engine.audit_line(f'type=USER_START msg=audit({now-.2}:1): pid=100 uid=0 auid={actor_uid} ses=424242 msg=\'op=PAM:session_open acct="{actor}" exe="/usr/sbin/sshd" addr={ip} terminal=ssh res=success\'')
                engine.audit_line(f'type=SYSCALL msg=audit({now-.1}:2): success=yes pid=200 ppid=100 uid=0 auid={actor_uid} ses=424242 exe="/usr/sbin/useradd" key="lab_root_exec"')
                engine.audit_line(f'type=ADD_USER msg=audit({now}:3): pid=200 uid=0 auid={actor_uid} ses=424242 msg=\'op=adding user acct="{target}" res=success\'')
                engine.tick(time.time()+3)
            row=store.db.execute("SELECT id,version,evidence_json FROM cases WHERE kind='ssh_session_account' ORDER BY created_at DESC LIMIT 1").fetchone()
            if not row:raise RuntimeError('Fixture chain was not correlated')
            identifier,version,evidence=row;data=json.loads(evidence)
            check('synthetic_chain_has_three_scoped_actions',[x['action'] for x in data['allowed_actions']]==['quarantine_account','terminate_session','block_ip'])
            result={'case_id':identifier,'version':version,'snapshot_hash':hashlib.sha256(evidence.encode()).hexdigest(),
                    'completed_at':time.time(),'status':'complete','model':'synthetic-test-verdict',
                    'analysis':{'summary':'Controlled fixture: failed logins, SSH session and account creation.',
                    'uncertainty':'Synthetic evidence; this is not a model evaluation.','attack':True,'confidence':.95,
                    'evidence_ids':[e['event_id'] for e in data['events']],'proposed_actions':data['allowed_actions']}}
            engine.apply_analysis(identifier,version,evidence,result)
            status,raw=store.db.execute('SELECT status,result_json FROM cases WHERE id=?',(identifier,)).fetchone()
            steps=json.loads(raw)
            check('real_executor_completed_authorized_plan',status=='defended' and all(x['status']=='executed' for x in steps))
            check('real_account_quarantined',pwd.getpwnam(target).pw_shell=='/usr/sbin/nologin')
            check('real_network_connection_blocked',not reachable())
            try:
                agent.request_executor(config,{'case_id':identifier,'position':2,'version':version})
                raise AssertionError('Completed step unexpectedly accepted')
            except RuntimeError:check('completed_step_cannot_be_replayed',True)
            receipt=steps[-1]['result']['undo_receipt'];journal=Journal(config);plan=journal.plan(receipt)
            journal.apply(receipt,plan['confirmation'],'Controlled isolated VM test')
            check('rollback_restores_real_network_connection',reachable())
            store.db.close();store=None
    finally:
        if store:store.db.close()
        if executor:
            executor.terminate();executor.wait(timeout=10)
        if server:server.close()
        run('nft','delete','element','inet','defense_lab','blocked4','{',ip,'}',check=False)
        run('ip','netns','delete',namespace,check=False)
        run('ip','link','delete',host,check=False)
        for name in reversed(users):run('userdel',name,check=False)


if __name__=='__main__':main()
