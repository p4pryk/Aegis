#!/usr/bin/env python3
"""Check bounded file intake and noisy-session correlation in an isolated VM database."""
import datetime,json,os,pathlib,socket,sys,tempfile,time
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
            files.close();safe=root/'recovery.jsonl'
            def app_line(user):return json.dumps({'time':time.time(),'event':'security_alert','user':user})+'\n'
            safe.write_text(app_line('before'));safe.chmod(0o600)
            config['application_sources']=[dict(name='recovery',application='lab3',path=str(safe),format='jsonl',owner_uid=0)]
            files=application_sources.Applications(engine);files.poll(True)
            safe.chmod(0o666)
            with safe.open('a') as out:out.write(app_line('untrusted'))
            files.poll(True);down=files.health['recovery']['status']=='DOWN' and str(safe) not in files.handles
            safe.rename(root/'unsafe-old');safe.write_text(app_line('after'));safe.chmod(0o600);files.poll(True)
            users={json.loads(row[0]).get('user') for row in store.db.execute("SELECT details_json FROM correlation_events WHERE kind='application_event' AND subject='lab3'")}
            check('Application reader recovers a safe replacement without consuming unsafe records',down and users=={'before','after'} and files.health['recovery']['status']=='GAP')
            files.close();files=application_sources.Applications(engine);files.poll(True)
            check('Unsafe application-file gap survives reader restart',files.health['recovery']['status']=='GAP')
            syslog=root/'auth.log';syslog.write_bytes(b'\xff\n');syslog.chmod(0o600)
            sysfiles=file_logs.Files(engine,{'auth':str(syslog)})
            try:
                sysfiles.poll(True);sysfiles.close();sysfiles=file_logs.Files(engine,{'auth':str(syslog)});sysfiles.poll(True)
                check('Invalid system-log UTF-8 also remains a visible gap',(sysfiles.health['auth']['invalid'],sysfiles.health['auth']['status'])==(1,'GAP'))
            finally:sysfiles.close()
            syslog=root/'recover-auth.log';stamp=datetime.datetime.now().astimezone().isoformat()
            def sys_line(user):return stamp+' host login: authentication failure user='+user+'\n'
            syslog.write_text(sys_line('alice'));syslog.chmod(0o600);sysfiles=file_logs.Files(engine,{'auth':str(syslog)})
            try:
                sysfiles.poll(True);syslog.chmod(0o666)
                with syslog.open('a') as out:out.write(sys_line('unsafe'))
                sysfiles.poll(True);down=sysfiles.health['auth']['status']=='DOWN' and str(syslog) not in sysfiles.handles
                syslog.rename(root/'auth-unsafe-old');syslog.write_text(sys_line('bob'));syslog.chmod(0o600);sysfiles.poll(True)
                subjects={row[0] for row in store.db.execute('SELECT subject FROM observations WHERE source=?',(str(syslog),))}
                check('System reader recovers a safe replacement with a visible gap',down and subjects=={'alice','bob'} and sysfiles.health['auth']['status']=='GAP')
            finally:sysfiles.close()
            now=time.time();login=engine.normalize('ssh_session_open','session',{'boot_id':engine.boot_id,'session':'42','auid':'1002'},'login',now-60)
            relevant=engine.normalize('sudo_command','actor',{'boot_id':engine.boot_id,'audit_session':'42','auid':'1002'},'matching',now-50);engine.remember(relevant)
            other=json.dumps({'boot_id':engine.boot_id,'audit_session':'99','auid':'1002'})
            store.db.executemany('INSERT INTO correlation_events VALUES (?,?,?,?,?)',[('noise:'+str(n),now-1,'sudo_command','other',other) for n in range(3000)]);store.db.commit()
            before=time.monotonic();found=telemetry.session_events(engine,login,now+1);elapsed=time.monotonic()-before
            check('Matching session survives 3000 newer events from another session',[e['event_id'] for e in found]==['matching'])
            check('Session attribution remains explicitly non-causal',telemetry.links([login,*found])[0]['relation']=='exact_audit_session_attribution_not_causal')
            print(json.dumps({'session_query_ms':round(elapsed*1000,2),'other_session_events':3000}))
            config['web_units']=['nginx.service','apache2.service']
            lineage=[engine.normalize('process_exec','pid',{'cgroup':'0::/system.slice/nginx.service'},'web-proc',now-3)]
            matching=engine.normalize('http_sqli_signature','192.0.2.50',{'boot_id':engine.boot_id,'unit':'nginx.service'},'web-matching',now-2);engine.remember(matching)
            other=json.dumps({'boot_id':engine.boot_id,'unit':'apache2.service'})
            store.db.executemany('INSERT INTO correlation_events VALUES (?,?,?,?,?)',[('webnoise:'+str(n),now-.1,'http_sqli_signature','192.0.2.50',other) for n in range(80)]);store.db.commit()
            context=engine.web_context_events(lineage,now)
            check('HTTP context excludes SQL signals from other services even under noise',[e['event_id'] for e in context]==['web-matching'])
            config['web_context_units']={'nginx.service':['apache2.service']};context=engine.web_context_events(lineage,now)
            check('Explicit proxy mapping adds bounded context',len(context)==64 and context[0]['event_id']=='web-matching' and any(e['details']['unit']=='apache2.service' for e in context))
            account=engine.normalize('account_created','lab_target',{'account_uid':2000},'web-account',now)
            identifier=engine.create_or_append('web_shell_account','lab_target',account,[*lineage,*context])
            row=store.db.execute('SELECT id,kind,subject,version FROM cases WHERE id=?',(identifier,)).fetchone()
            with patch.object(engine,'lineage',return_value=lineage):evidence=engine.snapshot(*row)
            check('Mapped HTTP signals remain non-causal and cannot authorize action',not evidence['allowed_actions'] and any(edge['from'].startswith('webnoise:') for edge in evidence['edges']) and all(edge['relation']=='nearby_http_time_context_not_causal' for edge in evidence['edges']))
            case=engine.create_or_append('waf_threshold','192.0.2.50',matching)
            row=store.db.execute('SELECT id,kind,subject,version FROM cases WHERE id=?',(case,)).fetchone()
            check('SQL signature alone does not authorize a defensive response',not engine.snapshot(*row)['allowed_actions'])
        finally:files.close();store.db.close()
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
