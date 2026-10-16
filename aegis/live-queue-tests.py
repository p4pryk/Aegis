"""Installed VM viewer + isolated queue fixture. Never alter the live incident database."""
import hashlib,json,os,pathlib,subprocess,sys,tempfile,time
sys.path.insert(0,'/opt/defense-agent')
import agent,console,queue_view
checks=[]
def check(name,ok):
    checks.append(bool(ok));print(json.dumps({'test':name,'passed':bool(ok)}),flush=True)
    if not ok:raise AssertionError(name)
real=console.read_snapshot('/var/lib/defense-agent/incidents.db')
check('Installed core publishes response and queue timing policy',all(k in real['heartbeat'] for k in ('boot_id','analysis_window','queue_window')))
check('Installed viewer can read the live queue',real['queue_available'])
with tempfile.TemporaryDirectory(prefix='aegis-queue-fixture-') as directory:
    c=dict(agent.DEFAULTS,data_dir=directory,ai_results_dir=directory)
    store=agent.Store(c);engine=agent.CorrelatedEngine(c,store,None);now=time.time()
    with store.atomic():
        for n in range(55):
            key=f'{n:024x}'
            store.db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(key,now-100,now-100,'application_activity','isolated-queue-fixture',1,'awaiting_analysis','{"allowed_actions":[]}','{}','{}'))
            store.db.execute('INSERT INTO analysis_queue VALUES (?,?,?,?,?)',(key,1,now-100,engine.boot_id,'BUDGET EXHAUSTED'))
        store.state('heartbeat',dict(time=now,boot_id=engine.boot_id,analysis_window=90,queue_window=7200))
        store.state('correlation_overload',dict(time=now-20,rejections=4))
    data=console.read_snapshot(store.path)
    check('Queue includes 55 cases despite the 40-case overview limit',len(data['queue_rows'])==55 and len(data['cases'])==40)
    before=hashlib.sha256(store.path.read_bytes()).hexdigest()
    output=subprocess.run([sys.executable,'/opt/defense-agent/console.py','--database',str(store.path),'--queue','--snapshot','--width','120'],capture_output=True,text=True,check=True,timeout=10).stdout
    check('CLI prints every queued case',all(f'{n:024x}' in output for n in range(55)))
    check('CLI displays historical-only and overload warnings','HISTORICAL ONLY' in output and 'ENROLLMENT REFUSED' in output)
    check('Viewer does not modify the database',hashlib.sha256(store.path.read_bytes()).hexdigest()==before)
    a=console.render(data,120,42,mode='queue',now=now);b=console.render(data,120,42,mode='queue',offset=12,now=now)
    check('Scrolling preserves the shield header',a[:len(console.logo(120))+4]==b[:len(console.logo(120))+4] and a!=b)
    pathlib.Path('/tmp/aegis-queue-preview.txt').write_text('ISOLATED VM TEST FIXTURE / NOT LIVE INCIDENTS\n'+'\n'.join(a)+'\n')
    path=pathlib.Path(directory)/('0'*24+'-v1.json');os.mkfifo(path)
    # A separate process gives this regression a hard timeout even if FIFO handling breaks.
    code="import sys,json;sys.path.insert(0,'/opt/defense-agent');import agent;c=json.loads(sys.argv[1]);s=agent.Store(c);e=agent.CorrelatedEngine(c,s,None);e.tick();s.db.close()"
    subprocess.run([sys.executable,'-c',code,json.dumps(c)],check=True,timeout=10,capture_output=True)
    check('FIFO result rejected without blocking the core',store.db.execute('SELECT status FROM cases WHERE id=?',('0'*24,)).fetchone()[0]=='analysis_error')
    store.db.close()
print(json.dumps({'passed':sum(checks),'total':len(checks)}))
