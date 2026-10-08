#!/usr/bin/env python3
"""Real SSH, sudo, group and file metadata test on the isolated training VM only."""
import json,os,pathlib,pwd,shutil,sqlite3,subprocess,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import console

DB='/var/lib/defense-agent/incidents.db'
results=[];suffix=str(time.time_ns())[-9:];actor='lab_tel_'+suffix;group='lab_tg_'+suffix
root=pathlib.Path('/tmp/aegis-telemetry-'+suffix)
sudo=pathlib.Path('/etc/sudoers.d/lab_tel_'+suffix)
cron=pathlib.Path('/etc/cron.d/lab_aegis_tel_'+suffix)
unit=pathlib.Path('/etc/systemd/system/lab-aegis-tel-'+suffix+'.timer')
rule=pathlib.Path('/etc/sudoers.d/lab_meta_'+suffix)
processes=[];created=False;group_created=False


def cmd(args,check=True):return subprocess.run(args,check=check,text=True,capture_output=True,timeout=20)


def query(sql,args=()):
    with sqlite3.connect(DB,timeout=5) as db:
        db.row_factory=sqlite3.Row
        return [dict(r) for r in db.execute(sql,args)]


def wait(fn,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        value=fn()
        if value:return value
        time.sleep(.3)
    raise AssertionError('Timed out waiting for telemetry')


def check(name,passed):
    results.append({'test':name,'passed':bool(passed)});print(json.dumps(results[-1]),flush=True)
    if not passed:raise AssertionError(name)


def main():
    global created,group_created
    if os.geteuid()!=0:raise SystemExit('Run as root on the isolated training VM')
    root.mkdir(mode=0o755)
    cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'key')])
    cmd(['useradd','-m','-s','/bin/bash',actor]);created=True
    cmd(['usermod','-p','*',actor]);cmd(['groupadd',group]);group_created=True
    home=pathlib.Path(pwd.getpwnam(actor).pw_dir);sshdir=home/'.ssh';sshdir.mkdir(mode=0o700)
    (sshdir/'authorized_keys').write_text((root/'key.pub').read_text());cmd(['chown','-R',actor+':'+actor,str(sshdir)])
    # Inert artifacts only; no cron job, service, privilege grant or extra authorized key.
    script=root/'mutate.py'
    script.write_text('import os,pathlib,subprocess\n'+
        f'subprocess.run(["/usr/sbin/usermod","-aG",{group!r},{actor!r}],check=True)\n'+
        f'pathlib.Path({str(rule)!r}).write_text("# AEGIS metadata test only\\n")\n'+
        f'pathlib.Path({str(rule)!r}).chmod(0o440)\n'+
        f'pathlib.Path({str(cron)!r}).write_text("# AEGIS inactive cron fixture\\n")\n'+
        f'pathlib.Path({str(unit)!r}).write_text("[Unit]\\nDescription=AEGIS inactive telemetry fixture\\n[Timer]\\nOnBootSec=100y\\n")\n'+
        f'os.chdir({str(sshdir)!r});os.chmod("authorized_keys",0o600)\n')
    sudo.write_text(f'{actor} ALL=(root) NOPASSWD: /usr/bin/python3 {script}, /usr/bin/true\n');sudo.chmod(0o440)
    cmd(['visudo','-cf',str(sudo)])
    prefix=['ssh','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=3','-i',str(root/'key'),actor+'@127.0.0.1']
    started=time.time()
    idle=subprocess.Popen(prefix+['sudo /usr/bin/true; sleep 90'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);processes.append(idle)
    sessions=lambda:query("SELECT * FROM ssh_sessions WHERE event_time>=? AND json_extract(details_json,'$.user')=?",(started,actor))
    idle_session=wait(sessions)[0]['identity']
    cmd(prefix+['sudo /usr/bin/python3 '+str(script)])
    changes=lambda:query("SELECT * FROM correlation_events WHERE event_time>=? AND kind IN ('identity_change','security_file_change','persistence_change')",(started,))
    def complete():
        rows=changes();paths={json.loads(r['details_json']).get('path') for r in rows}
        return rows if {str(rule),str(cron),str(unit),str(sshdir/'authorized_keys'),'/etc/group'}<=paths else None
    rows=wait(complete)
    check('Real group mutation recorded',any(r['kind']=='identity_change' and json.loads(r['details_json']).get('auid')==str(pwd.getpwnam(actor).pw_uid) and 'group' in json.loads(r['details_json']).get('op','') for r in rows))
    for name,path in (('Sudoers metadata',rule),('Cron metadata',cron),('Systemd timer metadata',unit),('Relative authorized_keys chmod',sshdir/'authorized_keys')):
        check(name,any(json.loads(r['details_json']).get('path')==str(path) for r in rows))
    cases=lambda:query("SELECT * FROM cases WHERE kind='host_change' AND created_at>=? AND json_array_length(evidence_json,'$.events')>0",(started,))
    def linked():
        for case in cases():
            events=json.loads(case['evidence_json']).get('events',[])
            kinds={e['kind'] for e in events};paths={e['details'].get('path') for e in events}
            if {'ssh_session_open','sudo_command','identity_change'}<=kinds and {str(rule),str(cron),str(unit)}<=paths:return case
    case=wait(linked);evidence=json.loads(case['evidence_json']);events=evidence['events']
    check('One chain joins SSH sudo group and persistence files',bool(events))
    check('Other session on same user and IP excluded',all(e['subject']!=idle_session for e in events) and idle.poll() is None)
    check('Changes alone authorize no response',not evidence['allowed_actions'] and case['status'] not in ('recognized','defended'))
    check('Session attribution labelled without causal overclaim',any(e['relation']=='exact_audit_session_attribution_not_causal' for e in evidence['edges']))
    text='\n'.join(console.chain_lines({'cases':[case]},120,case['id']))
    check('Terminal explains chronology links and response gate',all(s in text for s in ('RECORDED FACTS','[ATTRIBUTION]','DECISION / RESPONSE GATE','No response authorized')))
    check('No key or file contents enter normalized evidence','ssh-ed25519' not in json.dumps(evidence) and 'inactive cron fixture' not in json.dumps(evidence))
    restarted=time.time();cmd(['systemctl','restart','defense-agent'])
    wait(lambda:query("SELECT * FROM state WHERE key='heartbeat' AND json_extract(value,'$.time')>?",(restarted,)))
    snapshot=console.read_snapshot(DB,case['id']);retained=next(c for c in snapshot['cases'] if c['id']==case['id'])
    check('Chain remains inspectable after core restart',len(json.loads(retained['evidence_json'])['events'])>=len(events))
    def assessed():
        rows=query('SELECT * FROM cases WHERE id=?',(case['id'],))
        return rows[0] if rows and json.loads(rows[0]['analysis_json']).get('summary') else None
    assessed_case=wait(assessed,120)
    check('Real model describes the chain without authorizing new actions',not json.loads(assessed_case['analysis_json']).get('proposed_actions') and assessed_case['status'] not in ('recognized','defended'))
    (root/'chain.txt').write_text(text)
    pathlib.Path('/tmp/aegis-telemetry-chain.txt').write_text(text)


if __name__=='__main__':
    try:main()
    finally:
        for process in processes:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        for path in (sudo,rule,cron,unit):path.unlink(missing_ok=True)
        if created:cmd(['pkill','-u',actor],False);cmd(['userdel','-r',actor],False)
        if group_created:cmd(['groupdel',group],False)
        shutil.rmtree(root,ignore_errors=True)
        pathlib.Path('/tmp/aegis-telemetry-results.json').write_text(json.dumps(results,indent=2))
