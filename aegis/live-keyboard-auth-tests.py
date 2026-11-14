#!/usr/bin/env python3
"""Exercise real PAM keyboard-interactive SSH on the isolated AEGIS VM."""
import json,os,pathlib,pwd,secrets,shutil,socket,sqlite3,subprocess,tempfile,time
DB='/var/lib/defense-agent/incidents.db';checks=[]
def cmd(args,check=True,**kwargs):return subprocess.run(args,check=check,text=True,capture_output=True,timeout=25,**kwargs)
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
def query(sql,args=()):
    with sqlite3.connect(DB,timeout=5) as db:return db.execute(sql,args).fetchall()
def wait(fn,seconds=45):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=fn()
        if result:return result
        time.sleep(.3)
    raise AssertionError('Timed out waiting for keyboard-interactive SSH evidence')
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    suffix=str(time.time_ns())[-7:];user='lab_kbd_'+suffix;ns='ak'+suffix;host='ah'+suffix;peer='ap'+suffix
    ip='10.252.75.2';dst='10.252.75.1';port='22229';root=pathlib.Path(tempfile.mkdtemp(prefix='aegis-kbd-'));started=time.time()-1
    account=network=link=False;server=client=None;password=secrets.token_urlsafe(18)
    try:
        cmd(['useradd','-m','-s','/bin/bash',user]);account=True
        cmd(['chpasswd'],input=user+':'+password+'\n')
        cmd(['ip','netns','add',ns]);network=True
        cmd(['ip','link','add',host,'type','veth','peer','name',peer]);link=True
        cmd(['ip','link','set',peer,'netns',ns]);cmd(['ip','addr','add',dst+'/30','dev',host]);cmd(['ip','link','set',host,'up'])
        cmd(['ip','netns','exec',ns,'ip','addr','add',ip+'/30','dev',peer]);cmd(['ip','netns','exec',ns,'ip','link','set',peer,'up']);cmd(['ip','netns','exec',ns,'ip','link','set','lo','up'])
        config=root/'sshd.conf';config.write_text('\n'.join(('Port '+port,'ListenAddress '+dst,'HostKey /etc/ssh/ssh_host_ed25519_key','PidFile '+str(root/'sshd.pid'),'UsePAM yes','KbdInteractiveAuthentication yes','PasswordAuthentication no','PubkeyAuthentication no','PermitRootLogin no','AllowUsers '+user,'LogLevel VERBOSE'))+'\n')
        cmd(['/usr/sbin/sshd','-t','-f',str(config)])
        server=subprocess.Popen(['/usr/sbin/sshd','-D','-f',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        time.sleep(.5)
        if server.poll() is not None:raise RuntimeError('Isolated SSH server exited before the test')
        askpass=root/'askpass';askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$AEGIS_TEST_PASSWORD"\n');askpass.chmod(0o700)
        env=dict(os.environ,SSH_ASKPASS=str(askpass),SSH_ASKPASS_REQUIRE='force',DISPLAY=':99',AEGIS_TEST_PASSWORD=secrets.token_urlsafe(18))
        prefix=['ip','netns','exec',ns,'ssh','-p',port,'-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','PreferredAuthentications=keyboard-interactive','-o','PubkeyAuthentication=no','-o','PasswordAuthentication=no','-o','NumberOfPasswordPrompts=1','-o','ConnectTimeout=3',user+'@'+dst]
        cmd(['nft','list','set','inet','defense_lab','blocked4'])
        failures=[cmd(prefix+['true'],False,env=env).returncode for _ in range(5)]
        wait(lambda:len(query("SELECT event_id FROM correlation_events WHERE kind='ssh_failure' AND subject=? AND event_time>=? AND json_extract(details_json,'$.user')=?",(ip,started,user)))>=5)
        env['AEGIS_TEST_PASSWORD']=password
        client=subprocess.Popen(prefix+['sleep 60'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def evidence():
            rows=query("SELECT evidence_json FROM cases WHERE kind='ssh_threshold' AND subject=? AND updated_at>=? ORDER BY updated_at DESC",(ip,started))
            for (raw,) in rows:
                data=json.loads(raw)
                if any(s.get('kind')=='ssh_success_after_failures' for s in data.get('signals',[])):return data
        data=wait(evidence)
        check('Five real keyboard-interactive failures precede a successful login',all(code!=0 for code in failures) and client.poll() is None)
        check('Agent correlates real PAM SSH failures and success',any(s['kind']=='ssh_success_after_failures' for s in data['signals']))
        check('This signal alone does not authorize a response',not data['allowed_actions'])
        check('The source remains unblocked',cmd(['nft','get','element','inet','defense_lab','blocked4','{',ip,'}'],False).returncode!=0)
    finally:
        for process in (client,server):
            if process and process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        if network:cmd(['ip','netns','del',ns],False)
        if link:cmd(['ip','link','del',host],False)
        if account:
            try:uid=pwd.getpwnam(user).pw_uid;cmd(['pkill','-KILL','-u',str(uid)],False)
            except KeyError:pass
            cmd(['userdel','-r',user],False)
        shutil.rmtree(root,ignore_errors=True)
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
