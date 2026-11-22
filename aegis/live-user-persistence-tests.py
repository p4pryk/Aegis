#!/usr/bin/env python3
"""Real, inert user-persistence file changes on the isolated AEGIS lab VM."""
import json,os,pathlib,pwd,shlex,shutil,socket,sqlite3,subprocess,tempfile,time
from lab_cleanup import remove_test_user
DB='/var/lib/defense-agent/incidents.db';checks=[]
def cmd(args,check=True,**kwargs):return subprocess.run(args,check=check,capture_output=True,text=True,timeout=30,**kwargs)
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
def query(sql,args=()):
    with sqlite3.connect(DB,timeout=5) as db:return db.execute(sql,args).fetchall()
def wait(fn,seconds=60):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=fn()
        if result:return result
        time.sleep(.3)
    raise AssertionError('Timed out waiting for user persistence evidence')
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    suffix=str(time.time_ns())[-8:];actor='lab_up_'+suffix;root=pathlib.Path(tempfile.mkdtemp(prefix='aegis-user-persistence-'));root.chmod(0o755)
    made=False;process=None;started=time.time()-1;marker='AEGIS_INERT_USER_'+suffix
    try:
        cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'key')])
        if os.path.lexists('/home/'+actor):raise RuntimeError('Test home already exists')
        cmd(['useradd','-m','-s','/bin/bash',actor]);made=True
        cmd(['usermod','-p','*',actor]);account=pwd.getpwnam(actor);home=pathlib.Path(account.pw_dir)
        shell=next((home/name for name in ('.bash_profile','.zshrc','.profile','.bashrc') if not (home/name).exists()),None)
        unit=home/'.config/systemd/user'/('aegis-lab-'+suffix+'.service')
        if shell is None or unit.exists():raise RuntimeError('No unused fixture path is available')
        sshdir=home/'.ssh';sshdir.mkdir(mode=0o700)
        (sshdir/'authorized_keys').write_text((root/'key.pub').read_text());cmd(['chown','-R',actor+':'+actor,str(sshdir)])
        fish=home/'.config/fish/config.fish';fish_drop=home/'.config/fish/conf.d'/('aegis-lab-'+suffix+'.fish');ssh_rc=sshdir/'rc'
        content='# '+marker+'\n';script=root/'mutate.py';gate=root/'delete-ready'
        script.write_text('import pathlib,time\n'+f'p=pathlib.Path({str(shell)!r});p.write_text({content!r})\n'+f'u=pathlib.Path({str(unit)!r});u.parent.mkdir(parents=True,exist_ok=True);u.write_text({content!r})\n'+f'paths={list(map(str,(fish,fish_drop,ssh_rc)))!r}\n'+f'\nfor raw in paths:\n pth=pathlib.Path(raw);pth.parent.mkdir(parents=True,exist_ok=True);pth.write_text({content!r})\n'+f'gate=pathlib.Path({str(gate)!r})\n'+'\nwhile not gate.exists():time.sleep(.1)\np.unlink()\n');script.chmod(0o644)
        prefix=['ssh','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=3','-i',str(root/'key'),actor+'@127.0.0.1']
        process=subprocess.Popen(prefix+['python3 '+shlex.quote(str(script))+' && sleep 45'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        paths={str(shell):'shell_startup',str(unit):'systemd_user',str(fish):'shell_startup',str(fish_drop):'shell_startup',str(ssh_rc):'ssh_user_rc'}
        def recorded():
            if process.poll() is not None:raise RuntimeError('SSH test process ended before the file changes: '+process.stderr.read()[:400])
            rows=query("SELECT subject,details_json FROM correlation_events WHERE kind='persistence_change' AND event_time>=?",(started,))
            matched=[(subject,json.loads(details)) for subject,details in rows if subject in paths]
            return matched if {subject for subject,_ in matched}==set(paths) else None
        rows=wait(recorded)
        check('Real SSH user writes five watched persistence locations',process.poll() is None and len(rows)>=5)
        check('Audit metadata identifies user and mechanism',all(details.get('mechanism')==paths[subject] and details.get('auid')==str(account.pw_uid) for subject,details in rows))
        def linked():
            found={}
            for subject,raw in query("SELECT subject,evidence_json FROM cases WHERE kind='persistence_change' AND updated_at>=?",(started,)):
                if subject not in paths:continue
                evidence=json.loads(raw);kinds={event.get('kind') for event in evidence.get('events',[])}
                if {'persistence_change','ssh_session_open'}<=kinds:found[subject]=evidence
            return found if set(found)==set(paths) else None
        evidence=wait(linked)
        check('All changes link to the audited SSH session',all(any(edge.get('relation')=='exact_audit_session_attribution_not_causal' for edge in item['edges']) for item in evidence.values()))
        check('Standalone changes authorize no action',all(not item['allowed_actions'] for item in evidence.values()))
        check('Fixture file contents are absent from evidence',marker not in json.dumps(evidence))
        gate.touch()
        def deletion():
            for subject,raw in query("SELECT subject,details_json FROM correlation_events WHERE kind='persistence_change' AND subject=? AND event_time>=?",(str(shell),started)):
                details=json.loads(raw)
                if details.get('operation')=='DELETE':return details
        removed=wait(deletion)
        def delete_case():
            for raw, in query("SELECT evidence_json FROM cases WHERE kind='persistence_change' AND subject=? ORDER BY created_at DESC",(str(shell),)):
                item=json.loads(raw)
                if any(e.get('details',{}).get('operation')=='DELETE' for e in item.get('events',[])):return item
        case=wait(delete_case)
        check('Real user-file deletion appears in the incident',not shell.exists() and removed.get('auid')==str(account.pw_uid))
        check('Deletion retains session attribution but grants no action',any(e.get('relation')=='exact_audit_session_attribution_not_causal' for e in case['edges']) and not case['allowed_actions'])
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        if process and process.stderr:process.stderr.close()
        try:
            if made:remove_test_user(actor)
        finally:shutil.rmtree(root,ignore_errors=True)
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
