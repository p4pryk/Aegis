import json,pathlib,sqlite3,subprocess,time,sys,pwd
sys.path.insert(0,'/opt/defense-agent')
from agent import safe_ip
NS='aegis-app-test';IP='10.252.79.2';HOST='10.252.79.1';CONFIG=pathlib.Path('/etc/defense-agent/config.json');original=CONFIG.read_text();suffix=str(int(time.time()))[-7:];names=['lab_http_ok'+suffix,'lab_http_bad'+suffix,'lab_http_ip'+suffix];checks=[];cases=[]
def run(args):return subprocess.run(args,capture_output=True,text=True,check=True).stdout
code="import urllib.request,urllib.error,json,sys; d=json.loads(sys.argv[2]); r=urllib.request.Request('http://10.252.79.1:8081'+sys.argv[1],data=json.dumps(d).encode(),headers={'Content-Type':'application/json'});\ntry: response=urllib.request.urlopen(r,timeout=5)\nexcept urllib.error.HTTPError as e: response=e\nprint(response.read().decode())"
def post(path,data):return json.loads(run(['ip','netns','exec',NS,'python3','-c',code,path,json.dumps(data)]))
def rows(sql,args=()):
    with sqlite3.connect('/var/lib/defense-agent/incidents.db',timeout=10) as db:db.row_factory=sqlite3.Row;return [dict(x) for x in db.execute(sql,args)]
def check(name,condition):
    checks.append({'test':name,'passed':bool(condition)});print(json.dumps(checks[-1]),flush=True)
    if not condition:raise AssertionError(name)
def blocked():return subprocess.run(['nft','get','element','inet','defense_lab','blocked4','{',IP,'}'],capture_output=True).returncode==0
def waitcase(user):
    end=time.time()+120
    while time.time()<end:
        found=rows("SELECT * FROM cases WHERE kind='app_sql_account' AND evidence_json LIKE ? ORDER BY created_at DESC LIMIT 1",('%'+user+'%',))
        if found and found[0]['status'] in ('defended','defense_error','analysis_error','observing','insufficient_evidence'):return found[0]
        time.sleep(.5)
    raise TimeoutError('No completed application chain for '+user)
try:
    run(['ip','netns','add',NS]);run(['ip','link','add','aveth0','type','veth','peer','name','aveth1']);run(['ip','link','set','aveth1','netns',NS]);run(['ip','addr','add',HOST+'/30','dev','aveth0']);run(['ip','link','set','aveth0','up']);run(['ip','netns','exec',NS,'ip','addr','add',IP+'/30','dev','aveth1']);run(['ip','netns','exec',NS,'ip','link','set','aveth1','up']);run(['ip','netns','exec',NS,'ip','link','set','lo','up'])
    bad=post('/login',{'username':'admin','password':'wrong'});check('Wrong password rejected',bad['status']==401 and not blocked())
    attempt=post('/login',{'username':"admin' UNION SELECT",'password':'x'});check('Malformed injection rejected without IP block',attempt['status']==401 and not blocked())
    valid=post('/login',{'username':'admin','password':'training-admin-only'});check('Legitimate login succeeds',valid['status']==200)
    created=post('/accounts',{'session':valid['session'],'user':names[0]});check('Legitimate account creation succeeds',created['status']==201)
    bypass=post('/login',{'username':"admin' --",'password':'incorrect'});check('Actual SQL authentication bypass succeeds',bypass['status']==200)
    time.sleep(4);check('SQL bypass alone does not block IP',not blocked())
    result=post('/accounts',{'session':bypass['session'],'user':names[1]});check('Bypassed session creates real Linux account',result['status']==201)
    case=waitcase(names[1]);cases.append(case);check('Correlated model assessment leads to verified defense',case['status']=='defended')
    actions=json.loads(case['result_json']);check('Default response quarantines account and revokes app session only',set(x['action']['action'] for x in actions)=={'quarantine_account','revoke_app_session'} and all(x['result']['verified'] for x in actions))
    check('Quarantined account has nologin shell',pwd.getpwnam(names[1]).pw_shell=='/usr/sbin/nologin');check('Shared source remains reachable and revoked session rejected',post('/accounts',{'session':bypass['session'],'user':'lab_http_denied'})['status']==403 and not blocked());check('Legitimate account remains unaffected',pwd.getpwnam(names[0]).pw_shell=='/bin/bash')
    cfg=json.loads(original);cfg['app_dedicated_source_ips']=[IP];CONFIG.write_text(json.dumps(cfg));run(['systemctl','restart','defense-agent'])
    bypass=post('/login',{'username':"admin' --",'password':'incorrect'});result=post('/accounts',{'session':bypass['session'],'user':names[2]});check('Dedicated-source account chain executes',result['status']==201)
    case=waitcase(names[2]);cases.append(case);check('Dedicated source gets verified IP block after full chain',case['status']=='defended' and blocked())
    try:post('/login',{'username':'admin','password':'wrong'});unreachable=False
    except subprocess.CalledProcessError:unreachable=True
    check('Real HTTP traffic is blocked',unreachable)
    for case in cases:
        history=rows('SELECT status,time FROM case_status_history WHERE case_id=? ORDER BY time',(case['id'],));recognized=next(x['time'] for x in history if x['status']=='recognized');results=json.loads(case['result_json']);check('Assessment is recorded before response '+case['id'],all(x['result']['executed_at']>=recognized for x in results))
except Exception as exc:
    print(json.dumps({'error':type(exc).__name__,'message':str(exc)}),flush=True)
    raise
finally:
    CONFIG.write_text(original);subprocess.run(['systemctl','restart','defense-agent'],capture_output=True)
    subprocess.run(['nft','delete','element','inet','defense_lab','blocked4','{',IP,'}'],capture_output=True)
    subprocess.run(['ip','netns','delete',NS],capture_output=True);subprocess.run(['ip','link','delete','aveth0'],capture_output=True)
    for name in names:subprocess.run(['userdel',name],capture_output=True)
    pathlib.Path('/tmp/aegis-app-test-results.json').write_text(json.dumps({'checks':checks,'cases':cases},indent=2))
