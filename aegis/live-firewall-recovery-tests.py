#!/usr/bin/env python3
"""Lab test: lost firewall acknowledgement in isolated network namespaces.

Earlier containment in this fixture is simulated. Only the scoped firewall operation
and a loopback-free veth connection are real; no model verdict or production SLA is
inferred. Execute exclusively on a designated isolated laboratory VM with no
AEGIS services or long-running tests active.
"""
import json
import os
import pathlib
import secrets
import socket
import subprocess
import sys
import tempfile
import time

import agent
import response
from rollback import Journal


def run(args,check=True,timeout=15):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if check and result.returncode:raise RuntimeError(args[0]+' failed: '+result.stderr[:300])
    return result


def require(name,value):
    print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)


def prepare_synthetic_case(engine,store,client_ip,label):
    now=time.time();event=engine.normalize('fixture','test',{},'fixture-'+label,now)
    identifier=engine.create_or_append('app_sql_persistence','fixture',event)
    version=store.db.execute('SELECT version FROM cases WHERE id=?',(identifier,)).fetchone()[0]
    actions=[{'action':'revoke_app_session','session':'a'*32},{'action':'block_ip','ip':client_ip}]
    evidence={'version':version,'events':[{'event_id':'e1'}],'allowed_actions':actions,'required_evidence_ids':['e1'],'policy':{'minimum_confidence':.85}}
    assessment={'attack':True,'confidence':.95,'evidence_ids':['e1'],'proposed_actions':actions}
    store.db.execute("UPDATE cases SET evidence_json=?,analysis_json=?,status='recognized' WHERE id=?",(json.dumps(evidence),json.dumps(assessment),identifier))
    response.prepare(engine,identifier,evidence)
    store.db.execute("UPDATE response_steps SET status='executed',result_json=? WHERE case_id=? AND position=0",(json.dumps({'verified':True,'synthetic':True}),identifier))
    store.db.execute("UPDATE response_steps SET status='running',attempts=1 WHERE case_id=? AND position=1",(identifier,));store.db.commit()
    return {'case_id':identifier,'position':1,'version':version}


def main():
    if os.geteuid()!=0 or socket.gethostname() not in ('defense-lab-01','aegis-fw-check'):raise SystemExit('Run as root on a designated isolated AEGIS test VM')
    # Refuse to disturb an active agent or its long-running lab checks.
    for unit in ('defense-agent.service','defense-response.service','aegis-soak-72h-r4.service','aegis-observe-7d-r4.service'):
        state=run(['systemctl','is-active','--quiet',unit],False).returncode
        if state==0:raise SystemExit('Stop the AEGIS services and complete both long-running tests first')
        if state not in (3,4):raise SystemExit('Cannot verify service state; refusing the test')
    tag=secrets.token_hex(3);server_ns='ars'+tag;client_ns='arc'+tag;server_if='as'+tag;client_if='ac'+tag
    octet=1+int(tag[:2],16)%200;server_ip=f'10.253.{octet}.1';client_ip=f'10.253.{octet}.2';port=18996
    created=[];owned_links={};executor=None;listener=None;store=None;measurements=[]
    try:
        for ns in (server_ns,client_ns):run(['ip','netns','add',ns]);created.append(ns)
        run(['ip','link','add',server_if,'type','veth','peer','name',client_if])
        for name in (server_if,client_if):owned_links[name]=(pathlib.Path('/sys/class/net')/name/'ifindex').read_text().strip()
        run(['ip','link','set',server_if,'netns',server_ns]);run(['ip','link','set',client_if,'netns',client_ns])
        for ns,interface,address in ((server_ns,server_if,server_ip),(client_ns,client_if,client_ip)):
            run(['ip','netns','exec',ns,'ip','addr','add',address+'/30','dev',interface])
            run(['ip','netns','exec',ns,'ip','link','set',interface,'up']);run(['ip','netns','exec',ns,'ip','link','set','lo','up'])
        listener_code='import socket,sys;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])));s.listen(16);\nwhile True:\n c,_=s.accept();c.close()'
        listener=subprocess.Popen(['ip','netns','exec',server_ns,sys.executable,'-u','-c',listener_code,server_ip,str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        probe_code='import socket,sys;s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=1);s.close()'
        def reachable():return run(['ip','netns','exec',client_ns,sys.executable,'-c',probe_code,server_ip,str(port)],False,5).returncode==0
        deadline=time.monotonic()+10
        while time.monotonic()<deadline and not reachable():
            if listener.poll() is not None:raise RuntimeError('Isolated listener exited')
            time.sleep(.1)
        require('isolated_connection_initially_reachable',reachable())
        with tempfile.TemporaryDirectory(prefix='aegis-fw-recovery-') as directory:
            root=pathlib.Path(directory);runtime=root/'run';runtime.mkdir();config_path=root/'config.json'
            config_path.write_text(json.dumps({'response_mode':'enforce','lab_response_enabled':True,
                'app_dedicated_source_ips':[client_ip],'block_seconds':120,'data_dir':str(root),'runtime_dir':str(runtime),
                'executor_socket':str(runtime/'executor.sock'),'ai_results_dir':str(root)}))
            config=agent.load_config(config_path);store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
            executor=subprocess.Popen(['ip','netns','exec',server_ns,sys.executable,str(pathlib.Path(agent.__file__)),'executor','--config',str(config_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            deadline=time.monotonic()+10
            while not pathlib.Path(config['executor_socket']).exists() and time.monotonic()<deadline:
                if executor.poll() is not None:raise RuntimeError('Isolated executor exited')
                time.sleep(.05)
            if not pathlib.Path(config['executor_socket']).exists():raise RuntimeError('Executor socket did not appear')
            send_code='import json,socket,sys;s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);s.settimeout(5);s.connect(sys.argv[1]);s.send(json.dumps(json.loads(sys.argv[2])).encode());s.close()'
            retry_code='import agent,json,sys;c=agent.load_config(sys.argv[1]);print(json.dumps(agent.request_executor(c,json.loads(sys.argv[2]))))'
            undo_code='import agent,json,sys;from rollback import Journal;c=agent.load_config(sys.argv[1]);j=Journal(c);p=j.plan(sys.argv[2]);print(json.dumps(j.apply(sys.argv[2],p["confirmation"],"Controlled isolated firewall recovery fixture")))'
            env=os.environ.copy();env['PYTHONPATH']=str(pathlib.Path(agent.__file__).resolve().parent)
            def isolated_python(code,*args,check=True):
                result=subprocess.run(['ip','netns','exec',server_ns,sys.executable,'-c',code,*args],capture_output=True,text=True,timeout=20,env=env)
                if check and result.returncode:raise RuntimeError('Isolated helper failed: '+result.stderr[:300])
                return result
            journal=Journal(config)
            def scenario(label):
                envelope=prepare_synthetic_case(engine,store,client_ip,label);start=time.monotonic()
                isolated_python(send_code,config['executor_socket'],json.dumps(envelope))
                receipt=None;deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    receipt=next((r for r in journal.entries() if r.get('context')==envelope and r.get('state')=='contained'),None)
                    if receipt:break
                    if executor.poll() is not None:raise RuntimeError('Executor exited before receipt')
                    time.sleep(.05)
                require(label+'_lost_reply_has_durable_receipt',bool(receipt))
                require(label+'_real_firewall_blocks_only_isolated_connection',not reachable())
                measurements.append(round((time.monotonic()-start)*1000,2))
                retry=json.loads(isolated_python(retry_code,str(config_path),json.dumps(envelope)).stdout)
                require(label+'_retry_returns_original_verified_receipt',retry.get('reconciled') is True and retry.get('undo_receipt')==receipt['id'])
                require(label+'_no_duplicate_receipt',sum(r.get('context')==envelope for r in journal.entries())==1)
                return envelope,receipt
            envelope,receipt=scenario('rollback')
            undo=json.loads(isolated_python(undo_code,str(config_path),receipt['id']).stdout)
            require('rollback_restores_connection',undo.get('state')=='restored' and reachable())
            require('restored_receipt_cannot_reblock',isolated_python(retry_code,str(config_path),json.dumps(envelope),check=False).returncode!=0 and reachable())
            envelope,receipt=scenario('changed')
            run(['ip','netns','exec',server_ns,'nft','delete','element','inet','defense_lab','blocked4','{',client_ip,'}'])
            require('independent_removal_restores_connection',reachable())
            require('changed_firewall_state_cannot_be_reblocked',isolated_python(retry_code,str(config_path),json.dumps(envelope),check=False).returncode!=0 and reachable())
            print(json.dumps({'scope':'Two synthetic authorization fixtures; real isolated firewall and executor, no model or end-to-end SLA.',
                              'send_to_observed_block_upper_bound_ms':measurements}),flush=True)
    finally:
        original_error=sys.exc_info()[1];cleanup_errors=[]
        if store:
            try:store.db.close()
            except Exception:cleanup_errors.append('fixture database')
        for process in (executor,listener):
            if process and process.poll() is None:
                try:
                    process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                except ProcessLookupError:pass
                except (OSError,subprocess.TimeoutExpired):cleanup_errors.append('fixture process')
        # Delete host-side leftovers only when their kernel identity still matches.
        for name,index in owned_links.items():
            try:current=(pathlib.Path('/sys/class/net')/name/'ifindex').read_text().strip()
            except FileNotFoundError:continue
            if current==index:
                try:
                    if run(['ip','link','delete',name],False).returncode:cleanup_errors.append('interface '+name)
                except (OSError,subprocess.TimeoutExpired):cleanup_errors.append('interface '+name)
        for ns in reversed(created):
            try:
                if run(['ip','netns','delete',ns],False).returncode:cleanup_errors.append('namespace '+ns)
            except (OSError,subprocess.TimeoutExpired):cleanup_errors.append('namespace '+ns)
        if cleanup_errors:
            detail='Fixture cleanup failed: '+', '.join(cleanup_errors)
            if original_error is not None:original_error.add_note(detail)
            else:raise RuntimeError(detail)
    print('ISOLATED_FIREWALL_RECOVERY_PASSED')


if __name__=='__main__':main()
