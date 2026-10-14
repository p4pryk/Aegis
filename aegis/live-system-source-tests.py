"""Isolated VM: installed system-log collection and read-only text fallback."""
import datetime,json,os,pathlib,sqlite3,subprocess,sys,tempfile,time
sys.path.insert(0,'/opt/defense-agent')
import agent,console,file_logs,system_sources
checks=[]
def check(name,condition):
    checks.append(bool(condition));print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)
def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=20,**kw)
def wait(query,args=()):
    until=time.monotonic()+20
    while time.monotonic()<until:
        with sqlite3.connect('/var/lib/defense-agent/incidents.db') as db:row=db.execute(query,args).fetchone()
        if row:return row
        time.sleep(.25)
    raise AssertionError('Expected live collector event did not arrive')
started=time.time();unit='aegis-log-check-'+str(int(started))
try:
    run(['systemd-run','--unit='+unit,'--collect','/usr/bin/false'])
    row=wait("SELECT kind,details_json FROM correlation_events WHERE kind='system_service' AND subject=? AND event_time>=?",(unit+'.service',started))
    check('Real systemd service transition reaches installed correlation store',json.loads(row[1])['transport']=='journal')
    run(['su','-s','/bin/sh','-c','true','nobody'])
    row=wait("SELECT kind FROM observations WHERE kind IN ('su_session_open','system_session') AND time>=?",(started,))
    check('Real PAM user-switch session remains visible',row[0] in ('su_session_open','system_session'))
    # Tagged fixture tests transport/parser integration, not a real kernel denial or cron execution.
    run(['logger','-t','CRON','(root) CMD (/usr/bin/echo AEGIS_SOURCE_SECRET)'])
    row=wait("SELECT details_json FROM correlation_events WHERE kind='system_schedule' AND event_time>=?",(started,))
    check('Cron fixture reaches live journal reader without command arguments','AEGIS_SOURCE_SECRET' not in row[0])
    snapshot=console.read_snapshot('/var/lib/defense-agent/incidents.db')
    check('Coverage is visible in read-only console snapshot',snapshot['sensor_health']['system_log_coverage']['mode']=='journal')
    with tempfile.TemporaryDirectory(prefix='aegis-files-') as directory:
        root=pathlib.Path(directory);config=dict(agent.DEFAULTS,data_dir=directory)
        store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,lambda _: (_ for _ in ()).throw(AssertionError('Unexpected response')))
        path=root/'auth.log';path.write_text('');path.chmod(0o640)
        files=file_logs.Files(engine,{'auth':str(path)})
        def append(message,mode='a'):
            with path.open(mode) as out:out.write(datetime.datetime.now().astimezone().isoformat()+' host sshd[11]: '+message+'\n')
        try:
            for _ in range(5):append('Failed password for alice from 192.0.2.51 port 22')
            append('Accepted password for alice from 192.0.2.51 port 22')
            files.poll(True)
            case=store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity'").fetchone()
            evidence=engine.snapshot(*case)
            check('Failure batch and later successful login share a review-only case',len(evidence['events'])==6 and not evidence['allowed_actions'])
            check('Text cannot fabricate boot or kernel session identity',all(not e['details'].get('boot_id') and 'audit_session' not in e['details'] for e in evidence['events']))
            files.close();files=file_logs.Files(engine,{'auth':str(path)});files.poll(True)
            check('Restart does not duplicate file events',store.db.execute('SELECT count(*) FROM observations').fetchone()[0]==6)
            path.rename(root/'auth.log.1');append('Failed password for bob from 192.0.2.52 port 22','w');path.chmod(0o640)
            files.poll(True);files.poll(True)
            check('Rename rotation reads replacement and reports continuity limits',files.health['auth']['status']=='GAP' and store.db.execute('SELECT count(*) FROM observations').fetchone()[0]==7)
            append('Failed password for carol from 192.0.2.53 port 22','w');files.poll(True)
            check('Copytruncate/regrowth is detected',store.db.execute('SELECT count(*) FROM observations').fetchone()[0]==8)
            for _ in range(100):append('Failed password for alice from 192.0.2.51 port 22')
            before=store.db.execute('SELECT count(*) FROM observations').fetchone()[0];files.poll(True)
            check('One source consumes at most 25 complete records per batch',store.db.execute('SELECT count(*) FROM observations').fetchone()[0]-before==25)
            check('Backlog is visible',files.health['auth']['pending']>0)
        finally:files.close();store.db.close()
    config_path=pathlib.Path('/etc/defense-agent/config.json');original=config_path.read_bytes()
    live_path=pathlib.Path('/var/log/aegis-file-source-check.log');actor='sourcecheck_'+str(int(started))
    try:
        config=json.loads(original);config.update(system_log_mode='files',system_log_paths={key:str(live_path) if key=='auth' else '/var/log/aegis-missing-'+key for key in system_sources.PATHS})
        live_path.write_text('');live_path.chmod(0o640);config_path.write_text(json.dumps(config))
        run(['systemctl','restart','defense-agent'])
        stamp=datetime.datetime.now().astimezone().isoformat()
        with live_path.open('a') as out:
            for _ in range(5):out.write(stamp+' host sshd[11]: Failed password for '+actor+' from 192.0.2.51 port 22\n')
            out.write(stamp+' host sshd[11]: Accepted password for '+actor+' from 192.0.2.51 port 22\n')
        wait("SELECT case_id FROM case_events WHERE subject=?",(actor,))
        wait("SELECT value FROM state WHERE key='sensor_health' AND json_extract(value,'$.system_log_coverage.mode')='files'")
        snapshot=console.read_snapshot('/var/lib/defense-agent/incidents.db')
        check('Running core discovers and consumes configured auth file',any(s.get('path')==str(live_path) and s.get('parsed',0)>=6 for s in snapshot['sensor_health']['sources']))
        check('Missing file sources are explicit',any(s['status']=='MISSING' for s in snapshot['sensor_health']['sources']))
        check('Journal SSH intake is disabled in file mode',next(s for s in snapshot['sensor_health']['sources'] if s['name']=='SSH journal')['status']=='DISABLED')
    finally:
        config_path.write_bytes(original);run(['systemctl','restart','defense-agent']);live_path.unlink(missing_ok=True)
    wait("SELECT value FROM state WHERE key='sensor_health' AND json_extract(value,'$.system_log_coverage.mode')='journal'")
    report=run(['runuser','-u','defense-ai','--','python3','/opt/defense-agent/console.py','--sources','--snapshot']).stdout
    check('Unprivileged source screen reports parser coverage','SYSTEM LOG COVERAGE' in report and 'Kernel OOM' in report)
finally:
    subprocess.run(['systemctl','stop',unit+'.service'],capture_output=True)
    subprocess.run(['systemctl','reset-failed',unit+'.service'],capture_output=True)
print(json.dumps({'passed':sum(checks),'total':len(checks)}))
