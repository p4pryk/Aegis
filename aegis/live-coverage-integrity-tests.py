#!/usr/bin/env python3
"""Check live watch inventory and an isolated audit-assembly gap on the lab VM."""
import json,os,pathlib,socket,sqlite3,sys,tempfile,time
from unittest.mock import patch
sys.path.insert(0,'/opt/defense-agent')
import agent,console,coverage_check,monitoring,persistence,release_check

DB='/var/lib/defense-agent/incidents.db';checks=[]
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
def wait(fn,seconds=80):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        result=fn()
        if result:return result
        time.sleep(.5)
    raise AssertionError('Timed out waiting for coverage probe')
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    facts=coverage_check.inventory()
    expected=[p for p in coverage_check.AUTH_WATCHES if pathlib.Path(p).exists()]
    check('Installed audit inventory finds each existing expected auth watch',facts['identity_watches'] is not None and bool(expected) and all(facts['identity_watches'].get(p) for p in expected))
    def running_report():
        with sqlite3.connect(DB,timeout=5) as db:row=db.execute("SELECT value FROM state WHERE key='sensor_health'").fetchone()
        health=json.loads(row[0]) if row else {};report=health.get('coverage_check',{})
        return report if report.get('time',0)>=time.time()-75 and all(any(r['name']=='Auth watch '+p and r['status']=='WATCH PRESENT' for r in report.get('rows',[])) for p in expected) else None
    report=wait(running_report)
    check('Running agent publishes per-path watch coverage',bool(report))
    simulated=dict(facts);simulated['identity_watches']=dict(facts['identity_watches']);simulated['identity_watches'][expected[0]]=False
    local_report=coverage_check.assess({'persistence_enabled':True},{'sources':[]},simulated)
    check('Missing expected watch is shown in terminal coverage',any(r['name']=='Auth watch '+expected[0] and r['status']=='RULES MISSING' for r in local_report['rows']) and 'RULES MISSING' in ' '.join(coverage_check.lines(local_report,120,time.time())))
    with tempfile.TemporaryDirectory(prefix='aegis-assembly-check-') as directory:
        root=pathlib.Path(directory);config=dict(agent.DEFAULTS,data_dir=directory,persistence_enabled=True)
        store=agent.Store(config)
        try:
            engine=agent.CorrelatedEngine(config,store,None);now=time.time()
            engine.persistence_pending={'incomplete':{'received':now-601}}
            persistence.audit(engine,'EOE',str(now),'1','')
            check('Expired multi-record audit group creates a durable gap',store.state('audit_assembly_gap')['expired_groups']==1)
            (root/'producer.json').write_text(json.dumps({'boot_id':engine.boot_id,'pid':123,'start_ticks':1}))
            class Spool:
                path=root/'spool.db'
                def health(self):return {'rows':0,'oldest_seconds':0,'dropped':0}
            journals={k:{'connected':True,'pid':124,'start_ticks':1} for k in ('ssh','journal_context')}
            with patch.object(monitoring,'process_state',return_value='running'),patch.object(monitoring,'service_active',return_value=True):
                sources=monitoring.source_states(engine,Spool(),journals,{},now,{'enabled':'1','lost':'0'})
            view={'sensor_health':{'time':now,'sources':sources}}
            text=' '.join(console.source_lines(view,120,now))
            check('Assembly gap appears in source health view',sources[0]['status']=='GAP' and 'file audit assembly gap: recorded' in text)
            store.state('heartbeat',{'time':now,'pid':123,'boot_id':engine.boot_id})
            store.state('sensor_health',{'time':now,'audit':{'enabled':'1','lost':'0'},'audit_spool':{'dropped':0},'sources':sources})
            sample=release_check.sample(store.db,now)
            check('Continuity gate rejects the recorded collection gap',not release_check.continuous(sample,None))
            engine=agent.CorrelatedEngine(config,store,None)
            check('Assembly gap survives collector recreation',engine.store.state('audit_assembly_gap')['expired_groups']==1)
        finally:store.db.close()
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
