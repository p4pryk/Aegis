"""Isolated VM only: real executor, private receipts and explicit root CLI rollback."""
import hashlib,json,os,pathlib,pwd,subprocess,sys,tempfile,time
sys.path.insert(0,'/opt/defense-agent')
from agent import load_config,request_executor
from rollback import account,Journal
c=load_config();journal=Journal(c);suffix=str(int(time.time()))[-7:]
user='lab_rb_'+suffix;fault_user='lab_rbf_'+suffix;cron=pathlib.Path('/etc/cron.d/lab_aegis_rb'+suffix)
unit=pathlib.Path('/etc/systemd/system/lab-aegis-rb'+suffix+'.service')
ns='aegis-rollback-test';ip='10.252.80.2';host='10.252.80.1';extra='10.252.80.3';server=None;checks=[]
def run(args,check=True):return subprocess.run(args,capture_output=True,text=True,check=check,timeout=15)
def check(name,condition):
    checks.append({'test':name,'passed':bool(condition)});print(json.dumps(checks[-1]),flush=True)
    if not condition:raise AssertionError(name)
def call(action):return request_executor(c,action)['undo_receipt']
def cli(op,identifier=None,**options):
    args=['python3','/opt/defense-agent/rollback.py',op]+([identifier] if identifier else [])
    for key,value in options.items():args+=['--'+key,str(value)]
    return run(args,False)
def plan(identifier):
    result=cli('plan',identifier)
    if result.returncode:raise RuntimeError(result.stderr)
    return json.loads(result.stdout)
def undo(identifier,confirmation=None):
    return cli('apply',identifier,confirm=confirmation or plan(identifier)['confirmation'],reason='Isolated VM rollback regression test')
def probe():
    code="import socket; s=socket.create_connection(('10.252.80.1',18082),timeout=1);s.close()"
    return run(['ip','netns','exec',ns,'python3','-c',code],False).returncode==0
try:
    run(['useradd','-M','-s','/bin/bash',user]);run(['usermod','-p','*',user])
    before=account(user);identifier=call({'action':'quarantine_account','user':user,'expected_uid':pwd.getpwnam(user).pw_uid})
    check('Account containment has a reversible receipt',journal.read(identifier)['eligible'])
    check('Unprivileged user cannot read rollback plans',run(['runuser','-u','defense-ai','--','python3','/opt/defense-agent/rollback.py','plan',identifier],False).returncode!=0)
    check('Receipt directory is root private',journal.root.stat().st_mode&0o777==0o700)
    approved=plan(identifier);result=undo(identifier,approved['confirmation']);check('Account undo succeeds',result.returncode==0)
    after=account(user);check('Original shell, expiry and password-lock state restored',all(after[k]==before[k] for k in ('passwd_hash','shadow_hash','uid','shell','expiry','locked')))
    check('Repeated account undo is a no-op',json.loads(undo(identifier,approved['confirmation']).stdout)['already_restored'])
    identifier=call({'action':'quarantine_account','user':user,'expected_uid':pwd.getpwnam(user).pw_uid});approved=plan(identifier)
    run(['usermod','-s','/bin/false',user]);result=undo(identifier,approved['confirmation'])
    check('Account drift refuses undo and preserves administrator change',result.returncode!=0 and pwd.getpwnam(user).pw_shell=='/bin/false')
    check('Refused undo records operator reason',journal.read(identifier)['history'][-1]['state']=='refused')
    run(['userdel',user]);run(['useradd','-M','-s','/bin/bash',user])
    check('Recreated account cannot use previous receipt',cli('plan',identifier).returncode!=0)
    run(['useradd','-M','-s','/bin/bash',fault_user]);run(['usermod','-p','*',fault_user])
    identifier=call({'action':'quarantine_account','user':fault_user,'expected_uid':pwd.getpwnam(fault_user).pw_uid});approved=plan(identifier)
    import rollback
    from unittest.mock import patch
    original_atomic=rollback.atomic
    def interrupted(path,*args,**kwargs):
        original_atomic(path,*args,**kwargs)
        if str(path)=='/etc/passwd':raise RuntimeError('Injected interruption after restoring shell')
    try:
        with patch.object(rollback,'atomic',side_effect=interrupted):journal.apply(identifier,approved['confirmation'],'Controlled interruption test')
        raise AssertionError('Expected injected interruption')
    except RuntimeError:pass
    state=account(fault_user)
    check('Interrupted account restore keeps password and expiry containment',state['shell']=='/bin/bash' and state['locked'] and state['expiry']=='1')
    check('Interrupted restore requires manual review and is not retried',journal.read(identifier)['state']=='undo_uncertain' and cli('plan',identifier).returncode!=0)
    for path,content in ((cron,'# Inert AEGIS rollback test\n'),(unit,'[Unit]\nDescription=Inert rollback test\n[Service]\nType=oneshot\nExecStart=/usr/bin/true\n')):
        path.write_text(content);path.chmod(0o640);digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if path==unit:run(['systemctl','daemon-reload'])
        identifier=call({'action':'quarantine_persistence','path':str(path),'sha256':digest});approved=plan(identifier)
        check(path.name+' removed before restore',not path.exists())
        if path==cron:
            path.symlink_to('/etc/hosts');result=undo(identifier,approved['confirmation'])
            check('Existing symlink destination is never overwritten',result.returncode!=0 and path.is_symlink());path.unlink()
        result=undo(identifier);check(path.name+' restored exactly',result.returncode==0 and path.read_text()==content and path.stat().st_mode&0o777==0o640)
        check('Quarantine evidence retained',pathlib.Path(journal.read(identifier)['backup']).exists())
        if path==unit:check('Restored systemd unit stays stopped',run(['systemctl','is-active','--quiet',path.name],False).returncode!=0)
    # Tamper with a separate quarantined backup; restoration must refuse it.
    identifier=call({'action':'quarantine_persistence','path':str(cron),'sha256':hashlib.sha256(cron.read_bytes()).hexdigest()})
    backup=pathlib.Path(journal.read(identifier)['backup']);original=backup.read_bytes();backup.write_bytes(b'# changed evidence\n')
    check('Changed quarantine backup refuses restore',cli('plan',identifier).returncode!=0 and not cron.exists());backup.write_bytes(original)
    run(['ip','netns','add',ns]);run(['ip','link','add','rbveth0','type','veth','peer','name','rbveth1']);run(['ip','link','set','rbveth1','netns',ns]);run(['ip','addr','add',host+'/30','dev','rbveth0']);run(['ip','link','set','rbveth0','up']);run(['ip','netns','exec',ns,'ip','addr','add',ip+'/30','dev','rbveth1']);run(['ip','netns','exec',ns,'ip','link','set','rbveth1','up']);run(['ip','netns','exec',ns,'ip','link','set','lo','up'])
    server=subprocess.Popen(['python3','-m','http.server','18082','--bind',host],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for _ in range(30):
        if probe():break
        time.sleep(.1)
    check('Probe reachable before block',probe())
    identifier=call({'action':'block_ip','ip':ip,'expires_at':time.time()+60});check('Owned IP block stops real traffic',not probe())
    result=undo(identifier);check('IP undo restores real traffic',result.returncode==0 and probe())
    first=call({'action':'block_ip','ip':extra,'expires_at':time.time()+60});call({'action':'block_ip','ip':extra,'expires_at':time.time()+60})
    check('Overlapping incident claim prevents early unblock',cli('plan',first).returncode!=0)
    identifier=call({'action':'block_ip','ip':ip,'expires_at':time.time()+60});approved=plan(identifier)
    run(['nft','delete','element','inet','defense_lab','blocked4','{',ip,'}']);run(['nft','add','element','inet','defense_lab','blocked4','{',ip,'timeout','60s','comment','"other-owner"','}'])
    check('Replacement IP block is not removed',undo(identifier,approved['confirmation']).returncode!=0 and not probe())
    run(['nft','delete','element','inet','defense_lab','blocked4','{',ip,'}'])
    check('Absent IP block is an idempotent no-op',undo(identifier).returncode==0 and probe())
    print(json.dumps({'passed':len(checks),'total':len(checks)}))
finally:
    if server:server.terminate();server.wait(timeout=5)
    for address in (ip,extra):run(['nft','delete','element','inet','defense_lab','blocked4','{',address,'}'],False)
    run(['ip','netns','delete',ns],False);run(['ip','link','delete','rbveth0'],False)
    run(['userdel',user],False);run(['userdel',fault_user],False)
    for path in (cron,unit):
        if os.path.lexists(path):path.unlink()
    run(['systemctl','daemon-reload'],False)
