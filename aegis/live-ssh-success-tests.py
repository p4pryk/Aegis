#!/usr/bin/env python3
"""Check a real failed-then-successful SSH sequence in an isolated lab namespace."""
import json,os,pathlib,pwd,shutil,socket,sqlite3,subprocess,sys,tempfile,time
sys.path.insert(0,'/opt/defense-agent')
import agent

DB='/var/lib/defense-agent/incidents.db';checks=[]
def cmd(args,check=True):return subprocess.run(args,check=check,capture_output=True,text=True,timeout=20)
def check(name,condition):
    checks.append(bool(condition));print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)
def query(sql,args=()):
    with sqlite3.connect(DB,timeout=5) as db:return db.execute(sql,args).fetchall()
def wait(fn,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        value=fn()
        if value:return value
        time.sleep(.3)
    raise AssertionError('Timed out waiting for SSH correlation')
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    suffix=str(time.time_ns())[-7:];user='lab_sc_'+suffix;ns='asc'+suffix;host='ah'+suffix;peer='ap'+suffix
    ip='10.252.76.2';dst='10.252.76.1';root=pathlib.Path(tempfile.mkdtemp(prefix='aegis-ssh-check-'));root.chmod(0o755)
    account=False;network=False;link=False;process=None;started=time.time()
    try:
        for key in ('good','bad'):cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/key)])
        cmd(['useradd','-m','-s','/bin/bash',user]);account=True
        cmd(['usermod','-p','*',user]);home=pathlib.Path(pwd.getpwnam(user).pw_dir);sshdir=home/'.ssh';sshdir.mkdir(mode=0o700)
        (sshdir/'authorized_keys').write_text((root/'good.pub').read_text());cmd(['chown','-R',user+':'+user,str(sshdir)])
        cmd(['ip','netns','add',ns]);network=True
        cmd(['ip','link','add',host,'type','veth','peer','name',peer]);link=True
        cmd(['ip','link','set',peer,'netns',ns]);cmd(['ip','addr','add',dst+'/30','dev',host]);cmd(['ip','link','set',host,'up'])
        cmd(['ip','netns','exec',ns,'ip','addr','add',ip+'/30','dev',peer]);cmd(['ip','netns','exec',ns,'ip','link','set',peer,'up']);cmd(['ip','netns','exec',ns,'ip','link','set','lo','up'])
        prefix=['ip','netns','exec',ns,'ssh','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=3']
        cmd(['nft','list','set','inet','defense_lab','blocked4'])
        codes=[cmd(prefix+['-i',str(root/'bad'),user+'@'+dst,'true'],False).returncode for _ in range(5)]
        wait(lambda:len(query("SELECT event_id FROM correlation_events WHERE kind='ssh_failure' AND subject=? AND event_time>=? AND json_extract(details_json,'$.user')=?",(ip,started,user)))>=5)
        process=subprocess.Popen(prefix+['-i',str(root/'good'),user+'@'+dst,'sleep 90'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def correlated():
            rows=query("SELECT evidence_json FROM cases WHERE kind='ssh_threshold' AND subject=? AND updated_at>=? ORDER BY updated_at DESC",(ip,started))
            for (raw,) in rows:
                evidence=json.loads(raw)
                if any(s.get('kind')=='ssh_success_after_failures' and s.get('failure_count',0)>=5 for s in evidence.get('signals',[])):return evidence
        evidence=wait(correlated)
        check('Five failed SSH attempts preceded a successful login',all(c!=0 for c in codes) and process.poll() is None)
        check('Same-account and same-IP pattern appears in incident evidence',any(s['kind']=='ssh_success_after_failures' for s in evidence['signals']))
        check('Pattern alone authorizes no action',not evidence['allowed_actions'])
        check('Source is not blocked for the pattern alone',cmd(['nft','get','element','inet','defense_lab','blocked4','{',ip,'}'],False).returncode!=0)
        # Replay real normalized SSH records out of order into a disposable database.
        records=query("SELECT kind,event_time,event_id FROM correlation_events WHERE kind IN ('ssh_failure','ssh_success') AND subject=? AND event_time>=? AND json_extract(details_json,'$.user')=? ORDER BY event_time",(ip,started,user))
        success=next(row for row in records if row[0]=='ssh_success');failures=[row for row in records if row[0]=='ssh_failure']
        isolated=root/'isolated';isolated.mkdir();config=dict(agent.DEFAULTS,data_dir=str(isolated),protected_ips=[])
        store=agent.Store(config)
        try:
            engine=agent.CorrelatedEngine(config,store,None)
            engine.ssh_success(ip,user,success[1],success[2])
            store.db.execute("UPDATE cases SET created_at=? WHERE kind='ssh_threshold'",(time.time()-121,));store.db.commit()
            engine=agent.CorrelatedEngine(config,store,None)
            for _,stamp,identifier in failures:engine.failure('ssh',ip,stamp,identifier,user=user)
            row=store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='ssh_threshold' ORDER BY created_at DESC LIMIT 1").fetchone()
            replay=engine.snapshot(*row)
            check('Real SSH records rejoin after out-of-order replay and restart',any(s['kind']=='ssh_success_after_failures' for s in replay['signals']) and not replay['allowed_actions'])
        finally:store.db.close()
    finally:
        if process:
            process.terminate()
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait()
        if network:cmd(['ip','netns','del',ns],False)
        if link:cmd(['ip','link','del',host],False)
        if account:cmd(['userdel','-r',user],False)
        shutil.rmtree(root,ignore_errors=True)
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
