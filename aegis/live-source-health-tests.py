#!/usr/bin/env python3
"""Isolated VM acceptance test: stop/resume collectors without deleting evidence."""
import json,os,pathlib,signal,subprocess,sys,time
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import console
from monitoring import visible_sources
DB='/var/lib/defense-agent/incidents.db';results=[];stopped=[]

def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=15)

def snapshot():return console.read_snapshot(DB)

def source(name):return next((s for s in snapshot().get('sensor_health',{}).get('sources',[]) if s['name']==name),{})

def wait(fn,seconds=40):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        value=fn()
        if value:return value
        time.sleep(.3)
    raise AssertionError('Timed out waiting for source health')

def check(name,condition):
    results.append({'test':name,'passed':bool(condition)});print(json.dumps(results[-1]),flush=True)
    if not condition:raise AssertionError(name)

def save(label):
    data=snapshot();data['captured_at']=time.time();data['cases']=[];data['observations']=[]
    pathlib.Path('/tmp/aegis-sources-'+label+'.json').write_text(json.dumps(data))

if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Run as root on the isolated VM')
    ai=subprocess.run(['systemctl','is-active','--quiet','defense-agent-ai']).returncode==0
    run('systemctl','stop','defense-agent-ai')
    broker_stopped=False
    try:
        wait(lambda:len(snapshot().get('sensor_health',{}).get('sources',[]))==4)
        check('All four sources available',all(source(n)['status'] in ('LIVE','QUIET','GAP') for n in ('Kernel audit','SSH journal','Service journal','Application')))
        check('Quiet SSH reader is not treated as disconnected',wait(lambda:source('SSH journal').get('status')=='QUIET',45))
        save('live')
        pid=snapshot()['sensor_health']['journal']['pid'];os.kill(pid,signal.SIGSTOP);stopped.append(pid)
        check('Stopped SSH collector detected despite connected pipe',wait(lambda:source('SSH journal').get('status')=='DOWN'))
        save('down');os.kill(pid,signal.SIGCONT);stopped.remove(pid)
        check('SSH collector recovers without restart',wait(lambda:source('SSH journal').get('status') in ('LIVE','QUIET','GAP')))
        producer=json.loads(pathlib.Path('/var/lib/defense-agent-audit/producer.json').read_text())['pid']
        os.kill(producer,signal.SIGSTOP);stopped.append(producer)
        check('Stopped audit producer detected independently of old records',wait(lambda:source('Kernel audit').get('status')=='DOWN'))
        os.kill(producer,signal.SIGCONT);stopped.remove(producer)
        check('Audit intake recovers',wait(lambda:source('Kernel audit').get('status') in ('LIVE','QUIET','GAP')))
        run('systemctl','stop','aegis-target-broker');broker_stopped=True
        check('Stopped app producer detected even with readable log',wait(lambda:source('Application').get('status')=='DOWN'))
        run('systemctl','start','aegis-target-broker','aegis-target');broker_stopped=False
        check('App producer recovery observed',wait(lambda:source('Application').get('status') in ('LIVE','QUIET','GAP')))
        core=snapshot()['heartbeat']['pid'];os.kill(core,signal.SIGSTOP);stopped.append(core)
        check('Stale core invalidates all previously healthy statuses',wait(lambda:all(s['status']=='STALE' for s in visible_sources(snapshot(),time.time())),25))
        save('stale');os.kill(core,signal.SIGCONT);stopped.remove(core)
        check('Fresh core status returns after resume',wait(lambda:all(s['status']!='STALE' for s in visible_sources(snapshot(),time.time()))))
        check('Source screen fits terminal bounds',all(len(console.render(snapshot(),120,42,mode='sources'))==42 for _ in range(2)))
    finally:
        for pid in stopped:
            try:os.kill(pid,signal.SIGCONT)
            except ProcessLookupError:pass
        if broker_stopped:run('systemctl','start','aegis-target-broker','aegis-target')
        if ai:run('systemctl','start','defense-agent-ai')
        pathlib.Path('/tmp/aegis-source-health-results.json').write_text(json.dumps(results,indent=2))
