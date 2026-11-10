#!/usr/bin/env python3
"""Read-only local AEGIS diagnostics. No network calls or raw log output."""
import argparse
import json
import pathlib
import re
import sqlite3
import time
from urllib.parse import urlsplit

import agent
import ai_worker
import application_sources
import monitoring
import system_sources


def diagnose(config_path,model_path,database_path,now=None):
    checks=[]
    def add(name,status,detail):checks.append({'name':name,'status':status,'detail':detail})
    try:
        config=agent.load_config(config_path)
        application_sources.sources(config);system_sources.discover(config)
        add('Configuration','OK','Policy and source settings checked; response mode: '+config['response_mode'].upper()+'.')
    except (OSError,ValueError,TypeError,KeyError):
        add('Configuration','UNKNOWN','Configuration unavailable or invalid; check local permissions and settings.')
    try:
        raw=pathlib.Path(model_path).read_text();model=json.loads(raw)
        if not isinstance(model,dict):raise ValueError('invalid')
        endpoint=urlsplit(model.get('endpoint',''));deployment=model.get('deployment')
        if endpoint.scheme!='https' or not endpoint.hostname or endpoint.username or endpoint.password or not isinstance(deployment,str) or not deployment.strip():raise ValueError('invalid')
        ai_worker.limits(model)
        add('Model configuration','OK','Configured; connectivity and model access were not tested.')
    except FileNotFoundError:
        add('Model configuration','WARN','Not configured; collection can continue without model assessments.')
    except (OSError,ValueError,TypeError,KeyError):
        add('Model configuration','UNKNOWN','Configuration unavailable or invalid; model access was not tested.')
    try:
        uri=pathlib.Path(database_path).resolve().as_uri()+'?mode=ro'
        with sqlite3.connect(uri,uri=True,timeout=2) as db:
            db.execute('PRAGMA query_only=ON')
            states={k:json.loads(v) for k,v in db.execute("SELECT key,value FROM state WHERE key IN ('heartbeat','sensor_health','model_health')")}
        now=time.time() if now is None else now
        heartbeat=states.get('heartbeat',{});stamp=heartbeat.get('time',0)
        if type(stamp) not in (int,float) or not 0<=now-stamp<15:
            add('Collector','UNKNOWN','Core heartbeat missing or stale; current state is unknown.')
        else:
            health=states.get('sensor_health',{});health_time=health.get('time',0)
            sources=monitoring.visible_sources(states,now)
            if type(health_time) not in (int,float) or not 0<=now-health_time<15 or not health.get('sources'):
                add('Collector','UNKNOWN','Source health missing or stale; current state is unknown.')
            else:
                valid=('LIVE','QUIET','DISABLED','DOWN','MISSING','GAP','LAGGING','STALE','UNKNOWN')
                seen=set();unhealthy=[];audit=None
                for source in sources:
                    name=source.get('name');status=source.get('status')
                    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_. /@:-]{1,128}',name) or name in seen or status not in valid:raise ValueError('invalid source')
                    seen.add(name)
                    if name=='Kernel audit':audit=status
                    if status not in ('LIVE','QUIET','DISABLED') or name=='Kernel audit' and status=='DISABLED':unhealthy.append(name+': '+status)
                if audit is None:raise ValueError('missing audit')
                if unhealthy:add('Collector','WARN','Review source health: '+', '.join(unhealthy)+'.')
                else:add('Collector','OK','Enabled collectors report LIVE or QUIET. QUIET does not prove logs are emitted.')
        model=states.get('model_health',{});model_stamp=model.get('time',0);status=model.get('status')
        allowed=('ANALYZING','IDLE','WAITING FOR MODEL','BUDGET EXHAUSTED','RESPONSE BUDGET RESERVED','MODEL UNAVAILABLE')
        if type(model_stamp) in (int,float) and 0<=now-model_stamp<45 and status in allowed:add('Model worker','OK' if status in ('ANALYZING','IDLE') else 'WARN',status+'.')
        else:add('Model worker','UNKNOWN','Current worker state unavailable.')
    except (OSError,ValueError,TypeError,KeyError,AttributeError,sqlite3.Error):
        add('Collector','UNKNOWN','Incident database or source status unavailable.')
        add('Model worker','UNKNOWN','Current worker state unavailable.')
    return {'checks':checks,'healthy':all(check['status']=='OK' for check in checks),'scope':'Local metadata only; no network or model connectivity check.'}


def main():
    parser=argparse.ArgumentParser(description='AEGIS local read-only diagnostics')
    parser.add_argument('--config',default='/etc/defense-agent/config.json')
    parser.add_argument('--model-config',default='/etc/defense-agent/ai.json')
    parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db')
    parser.add_argument('--json',action='store_true');args=parser.parse_args()
    result=diagnose(args.config,args.model_config,args.database)
    if args.json:print(json.dumps(result))
    else:
        print('AEGIS / LOCAL DIAGNOSTICS')
        for check in result['checks']:print('['+check['status']+'] '+check['name']+' — '+check['detail'])
        print(result['scope'])
    return 0 if result['healthy'] else 1

if __name__=='__main__':raise SystemExit(main())
