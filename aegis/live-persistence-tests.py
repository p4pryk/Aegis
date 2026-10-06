#!/usr/bin/env python3
"""Isolated, live acceptance test. Run as root only on the training VM."""
import json,os,pathlib,pwd,sqlite3,subprocess,sys,time
NS='aegis-persist-test';IP='10.252.80.2';HOST='10.252.80.1';STAMP=str(int(time.time()))[-7:]
APP='http://'+HOST+':8081';DB='/var/lib/defense-agent/incidents.db';checks=[];names=[];artifacts=[]
code="import urllib.request,urllib.error,json,sys;d=json.loads(sys.argv[2]);r=urllib.request.Request(sys.argv[1],data=json.dumps(d).encode(),headers={'Content-Type':'application/json'});\ntry: v=urllib.request.urlopen(r,timeout=8)\nexcept urllib.error.HTTPError as e:v=e\nprint(v.read().decode())"
def run(args,ok=(0,)):
    p=subprocess.run(args,capture_output=True,text=True,timeout=20)
    if p.returncode not in ok:raise RuntimeError('command failed '+args[0]+': '+p.stderr[:200])
    return p.stdout
def post(path,data):return json.loads(run(['ip','netns','exec',NS,'python3','-c',code,APP+path,json.dumps(data)]))
def query(sql,args=()):
    with sqlite3.connect(DB,timeout=5) as db:db.row_factory=sqlite3.Row;return [dict(x) for x in db.execute(sql,args)]
def check(name,condition):
    item={'test':name,'passed':bool(condition)};checks.append(item);print(json.dumps(item),flush=True)
    if not condition:raise AssertionError(name)
def wait_case(kind,fragment,seconds=75):
    end=time.time()+seconds
    while time.time()<end:
        found=query('SELECT * FROM cases WHERE kind=? AND evidence_json LIKE ? ORDER BY created_at DESC LIMIT 1',(kind,'%'+fragment+'%'))
        if found and found[0]['status'] in ('defended','defense_error','analysis_error','insufficient_evidence','observing','authorized'):return found[0]
        time.sleep(.5)
    raise TimeoutError('case '+kind+' '+fragment)
def create_ns():
    run(['ip','netns','add',NS]);run(['ip','link','add','pveth0','type','veth','peer','name','pveth1']);run(['ip','link','set','pveth1','netns',NS]);run(['ip','addr','add',HOST+'/30','dev','pveth0']);run(['ip','link','set','pveth0','up']);run(['ip','netns','exec',NS,'ip','addr','add',IP+'/30','dev','pveth1']);run(['ip','netns','exec',NS,'ip','link','set','pveth1','up']);run(['ip','netns','exec',NS,'ip','link','set','lo','up'])
def bypass():return post('/login',{'username':"admin' --",'password':'incorrect'})
def results(case):return json.loads(case['result_json'])
def main():
    create_ns();cfg=json.loads(pathlib.Path('/etc/defense-agent/config.json').read_text());check('Persistence sensor enabled',cfg.get('persistence_enabled') is True)
    valid=post('/login',{'username':'admin','password':'training-admin-only'});check('Legitimate session',valid['status']==200)
    legal='legal'+STAMP;legalpath='/etc/cron.d/lab_aegis_'+legal
    item=post('/persistence',{'session':valid['session'],'artifact':'cron','name':legal});artifacts.append(legalpath);check('Legal cron file created',item['status']==201 and pathlib.Path(legalpath).is_file())
    case=wait_case('persistence_change',legalpath);check('Legal file change recorded without automatic action',case['status'] in ('insufficient_evidence','authorized') and json.loads(case['evidence_json'])['allowed_actions']==[] and pathlib.Path(legalpath).exists())
    attempt=post('/persistence',{'session':valid['session'],'artifact':'cron','name':'../../bad'});check('Unscoped artifact request rejected',attempt['status']==400)
    attack=bypass();check('SQL bypass grants test session',attack['status']==200)
    shell=post('/shell',{'session':attack['session']});check('Application shell test executed',shell['status']==200)
    end=time.time()+8
    while time.time()<end and not query("SELECT id FROM cases WHERE kind='application_shell' AND created_at>?",(time.time()-20,)):time.sleep(.25)
    check('Unprivileged application shell observed by kernel audit',bool(query("SELECT id FROM cases WHERE kind='application_shell' AND created_at>?",(time.time()-20,))))
    cron='cron'+STAMP;cronpath='/etc/cron.d/lab_aegis_'+cron;item=post('/persistence',{'session':attack['session'],'artifact':'cron','name':cron});artifacts.append(cronpath)
    check('Bypassed session creates cron file',item['status']==201 and pathlib.Path(cronpath).exists())
    case=wait_case('app_sql_persistence',cronpath);actions=results(case)
    check('Correlated cron chain defended',case['status']=='defended' and {a['action']['action'] for a in actions}=={'quarantine_persistence','revoke_app_session'} and all(a['result']['verified'] for a in actions))
    check('Cron artifact removed from active path and preserved',not pathlib.Path(cronpath).exists() and any(pathlib.Path(a['result']['backup']).exists() for a in actions if a['action']['action']=='quarantine_persistence'))
    check('Only attack session revoked',post('/shell',{'session':attack['session']})['status']==403 and post('/login',{'username':'admin','password':'training-admin-only'})['status']==200)
    attack=bypass();label='svc'+STAMP;unit='lab-aegis-'+label+'.service';unitpath='/etc/systemd/system/'+unit
    item=post('/persistence',{'session':attack['session'],'artifact':'systemd','name':label});artifacts.append(unitpath)
    check('Bypassed session enables training systemd unit',item['status']==201 and run(['systemctl','is-active',unit]).strip()=='active')
    case=wait_case('app_sql_persistence',unitpath);actions=results(case)
    check('Correlated systemd chain defended',case['status']=='defended' and {a['action']['action'] for a in actions}=={'quarantine_persistence','revoke_app_session'} and all(a['result']['verified'] for a in actions))
    check('Training service stopped and unit quarantined',not pathlib.Path(unitpath).exists() and subprocess.run(['systemctl','is-active','--quiet',unit]).returncode!=0)
    user='lab_key'+STAMP;names.append(user);run(['useradd','-M','-s','/usr/sbin/nologin',user]);home=pathlib.Path('/home')/user;ssh=home/'.ssh';ssh.mkdir(parents=True,mode=0o700);key=ssh/'authorized_keys';key.write_text('# AEGIS training marker\n');key.chmod(0o600)
    end=time.time()+8
    while time.time()<end and not query("SELECT id FROM cases WHERE kind='persistence_change' AND subject=? ORDER BY created_at DESC LIMIT 1",(str(key),)):time.sleep(.25)
    found=query("SELECT * FROM cases WHERE kind='persistence_change' AND subject=? ORDER BY created_at DESC LIMIT 1",(str(key),))
    check('SSH authorized_keys change observed',bool(found))
    if found:
        evidence=json.loads(found[0]['evidence_json']) if found[0]['evidence_json']!='{}' else None
        check('SSH key change has no automatic destructive action',key.exists() and (not evidence or evidence['allowed_actions']==[]))
try:main()
finally:
    subprocess.run(['ip','netns','delete',NS],capture_output=True);subprocess.run(['ip','link','delete','pveth0'],capture_output=True)
    for path in artifacts:
        if path.endswith('.service'):
            subprocess.run(['systemctl','disable','--now',pathlib.Path(path).name],capture_output=True)
        pathlib.Path(path).unlink(missing_ok=True)
    for user in names:
        import shutil
        shutil.rmtree(pathlib.Path('/home')/user,ignore_errors=True);subprocess.run(['userdel',user],capture_output=True)
    pathlib.Path('/tmp/aegis-persistence-results.json').write_text(json.dumps(checks,indent=2))
