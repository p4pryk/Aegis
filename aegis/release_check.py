#!/usr/bin/env python3
"""Read-only duration-based acceptance report; never implies a longer soak passed."""
import argparse
import json
import pathlib
import sqlite3
import time

def sample(db, now=None):
    states={key:json.loads(value) for key,value in db.execute("SELECT key,value FROM state WHERE key IN ('heartbeat','sensor_health','model_health','correlation_overload')")}
    # SQLite may wait for a writer; compare against the clock after the read.
    now=time.time() if now is None else now
    try:
        health=states['sensor_health'];heartbeat=states['heartbeat']
        spool=health['audit_spool'];audit=health['audit']
        pid=heartbeat['pid'];boot=heartbeat['boot_id']
        if type(pid) is not int or pid<=0 or not isinstance(boot,str) or not boot:raise ValueError('Invalid collector identity')
        raw_lost=audit['lost']
        if not (type(raw_lost) is int or isinstance(raw_lost,str) and raw_lost.isdigit()):raise ValueError('Invalid kernel loss counter')
        dropped=spool['dropped'];lost=int(raw_lost);rejected=states.get('correlation_overload',{}).get('rejections',0)
        if any(type(v) is not int or v<0 for v in (dropped,lost,rejected)):raise ValueError('Invalid loss counter')
        health_time=health['time'];enabled=str(audit['enabled'])
        if type(health_time) not in (int,float) or enabled not in ('1','2'):raise ValueError('Audit health unavailable')
        sources=health['sources']
        if not isinstance(sources,list) or not sources:raise ValueError('Source health unavailable')
        statuses={}
        for source in sources:
            name=source['name'];status=source['status']
            if not isinstance(name,str) or not name or name in statuses or status not in ('LIVE','QUIET','DISABLED','DOWN','MISSING','GAP','LAGGING','STALE','UNKNOWN'):
                raise ValueError('Invalid source health')
            statuses[name]=status
        if 'Kernel audit' not in statuses:raise ValueError('Kernel audit collector missing')
        unhealthy=[name+': '+status for name,status in statuses.items() if status not in ('LIVE','QUIET','DISABLED') or name=='Kernel audit' and status=='DISABLED']
    except (KeyError,TypeError,OverflowError) as exc:raise ValueError('Incomplete collector health') from exc
    return {'time':now,'core_alive':0<=now-heartbeat.get('time',0)<15,
            'sensor_alive':0<=now-health_time<15,'core_pid':pid,'boot_id':boot,'unhealthy_sources':unhealthy,
            'response_mode':heartbeat.get('response_mode','unknown'),
            'core_p95_ms':health.get('loop_p95_ms'), 'audit_pending':spool.get('rows'),
            'spool_dropped':dropped,'kernel_lost':lost,'refused_cases':rejected,
            'model_status':states.get('model_health',{}).get('status','UNKNOWN')}

def continuous(item, previous):
    if not item['core_alive'] or not item['sensor_alive'] or item['unhealthy_sources']:return False
    if previous is None:return True
    if (item['boot_id'],item['core_pid'])!=(previous['boot_id'],previous['core_pid']):return False
    return all(item[key]==previous[key] for key in ('spool_dropped','kernel_lost','refused_cases'))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--seconds',type=int,default=120);parser.add_argument('--output',required=True);parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db');args=parser.parse_args()
    if not 10<=args.seconds<=7*86400:raise SystemExit('Duration must be between 10 seconds and seven days')
    path=pathlib.Path(args.output)
    # Never overwrite evidence from a previous run.
    with path.open('x') as out:
        db=sqlite3.connect('file:'+args.database+'?mode=ro',uri=True,timeout=2)
        started=time.monotonic();previous=None;failures=0;samples=0
        while True:
            try:
                item=sample(db);samples+=1
                if not continuous(item,previous):failures+=1
                previous=item
            except (sqlite3.Error,ValueError,TypeError):item={'time':time.time(),'error':'SAMPLE UNAVAILABLE'};failures+=1
            out.write(json.dumps(item)+'\n');out.flush()
            elapsed=time.monotonic()-started
            if elapsed>=args.seconds:break
            time.sleep(min(5,args.seconds-elapsed))
        report={'elapsed_seconds':round(elapsed,2),'requested_seconds':args.seconds,'samples':samples,'failed_samples':failures,'passed':failures==0 and samples>0,'scope':'collector continuity only; attack accuracy and model latency require separate tests'}
        out.write(json.dumps({'report':report})+'\n');print(json.dumps(report));db.close()
        if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
