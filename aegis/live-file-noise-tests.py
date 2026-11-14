#!/usr/bin/env python3
"""Check bounded file intake and noisy-session correlation in an isolated VM database."""
import json,os,pathlib,socket,sys,tempfile,time
from unittest.mock import patch
sys.path.insert(0,'/opt/defense-agent')
import agent,application_sources,file_logs,telemetry
checks=[]
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    with tempfile.TemporaryDirectory(prefix='aegis-file-integrity-') as directory:
        root=pathlib.Path(directory);path=root/'large.jsonl';path.touch(mode=0o600)
        source=dict(name='large',application='lab',path=str(path),format='jsonl',owner_uid=0)
        config=dict(agent.DEFAULTS,data_dir=directory,application_sources=[source],auto_access_logs=False)
        store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None);files=application_sources.Applications(engine)
        try:
            forged=json.dumps({'time':time.time(),'event':'security_alert','user':'forged'}).encode()
            real=json.dumps({'time':time.time(),'event':'security_alert','user':'real'}).encode()
            body=b'X'*(100+8193)+forged+b'\n'+real+b'\n'
            path.write_bytes(body+b'\n'*(1048676-len(body)));files.poll(True)
            events=store.db.execute("SELECT details_json FROM correlation_events WHERE kind='application_event'").fetchall()
            check('Oversized startup record cannot fabricate a suffix event',[json.loads(row[0])['user'] for row in events]==['real'])
            check('Bounded startup is reported as a collection gap',files.health['large']['status']=='GAP')
            cases=store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='application_activity'").fetchall()
            check('Real application event alone authorizes no action',len(cases)==1 and not engine.snapshot(*cases[0])['allowed_actions'])
            files.close()
            path=root/'invalid.jsonl';path.write_text('not-json\n'+json.dumps({'time':time.time(),'event':'unknown'})+'\n'+json.dumps({'time':time.time(),'event':'security_alert'})+'\n');path.chmod(0o600)
            config['application_sources']=[dict(name='invalid',application='lab2',path=str(path),format='jsonl',owner_uid=0)]
            files=application_sources.Applications(engine)
            with patch.object(application_sources,'ingest',side_effect=RuntimeError('simulated commit failure')):
                try:files.poll(True)
                except RuntimeError:pass
                else:raise AssertionError('Expected fixture transaction failure')
            check('Failed file transaction does not advance cursor or health counters',store.state(files.cursor_key('invalid',str(path))) is None and files.health['invalid']['invalid']==0)
            files.poll(True);h=files.health['invalid']
            check('Malformed and unsupported records are counted without raw payload',(h['invalid'],h['unrecognized'],h['status'])==(1,1,'GAP'))
            files.close();files=application_sources.Applications(engine);files.poll(True);h=files.health['invalid']
            check('File parser counters and GAP survive reopening',(h['invalid'],h['unrecognized'],h['status'])==(1,1,'GAP'))
            syslog=root/'auth.log';syslog.write_bytes(b'\xff\n');syslog.chmod(0o600)
            sysfiles=file_logs.Files(engine,{'auth':str(syslog)})
            try:
                sysfiles.poll(True);sysfiles.close();sysfiles=file_logs.Files(engine,{'auth':str(syslog)});sysfiles.poll(True)
                check('Invalid system-log UTF-8 also remains a visible gap',(sysfiles.health['auth']['invalid'],sysfiles.health['auth']['status'])==(1,'GAP'))
            finally:sysfiles.close()
            now=time.time();login=engine.normalize('ssh_session_open','session',{'boot_id':engine.boot_id,'session':'42','auid':'1002'},'login',now-60)
            relevant=engine.normalize('sudo_command','actor',{'boot_id':engine.boot_id,'audit_session':'42','auid':'1002'},'matching',now-50);engine.remember(relevant)
            other=json.dumps({'boot_id':engine.boot_id,'audit_session':'99','auid':'1002'})
            store.db.executemany('INSERT INTO correlation_events VALUES (?,?,?,?,?)',[('noise:'+str(n),now-1,'sudo_command','other',other) for n in range(3000)]);store.db.commit()
            before=time.monotonic();found=telemetry.session_events(engine,login,now+1);elapsed=time.monotonic()-before
            check('Matching session survives 3000 newer events from another session',[e['event_id'] for e in found]==['matching'])
            check('Session attribution remains explicitly non-causal',telemetry.links([login,*found])[0]['relation']=='exact_audit_session_attribution_not_causal')
            print(json.dumps({'session_query_ms':round(elapsed*1000,2),'other_session_events':3000}))
        finally:files.close();store.db.close()
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
