#!/usr/bin/env python3
"""Read-only duration-based acceptance report; never implies a longer soak passed."""
import argparse
import json
import pathlib
import sqlite3
import time

def sample(db, now):
    states={key:json.loads(value) for key,value in db.execute("SELECT key,value FROM state WHERE key IN ('heartbeat','sensor_health','model_health','correlation_overload')")}
    health=states.get('sensor_health',{});heartbeat=states.get('heartbeat',{})
    spool=health.get('audit_spool',{});audit=health.get('audit',{})
    return {'time':now,'core_alive':0<=now-heartbeat.get('time',0)<15,
            'response_mode':heartbeat.get('response_mode','unknown'),
            'core_p95_ms':health.get('loop_p95_ms'), 'audit_pending':spool.get('rows'),
            'spool_dropped':spool.get('dropped',0),'kernel_lost':int(audit.get('lost',0)),
            'refused_cases':states.get('correlation_overload',{}).get('rejections',0),
            'model_status':states.get('model_health',{}).get('status','UNKNOWN')}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--seconds',type=int,default=120);parser.add_argument('--output',required=True);parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db');args=parser.parse_args()
    if not 10<=args.seconds<=7*86400:raise SystemExit('Duration must be between 10 seconds and seven days')
    path=pathlib.Path(args.output)
    # Never overwrite evidence from a previous run.
    with path.open('x') as out:
        db=sqlite3.connect('file:'+args.database+'?mode=ro',uri=True,timeout=2)
        started=time.monotonic();first=None;last=None;failures=0;samples=0
        while True:
            try:
                item=sample(db,time.time());samples+=1;last=item
                if first is None:first=item
                if not item['core_alive'] or any(item[key]>first[key] for key in ('spool_dropped','kernel_lost','refused_cases')):failures+=1
            except (sqlite3.Error,ValueError,TypeError):item={'time':time.time(),'error':'SAMPLE UNAVAILABLE'};failures+=1
            out.write(json.dumps(item)+'\n');out.flush()
            elapsed=time.monotonic()-started
            if elapsed>=args.seconds:break
            time.sleep(min(5,args.seconds-elapsed))
        report={'elapsed_seconds':round(elapsed,2),'requested_seconds':args.seconds,'samples':samples,'failed_samples':failures,'passed':failures==0 and samples>0,'scope':'collector continuity only; attack accuracy and model latency require separate tests'}
        out.write(json.dumps({'report':report})+'\n');print(json.dumps(report));db.close()
        if not report['passed']:raise SystemExit(1)

if __name__=='__main__':main()
