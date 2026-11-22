#!/usr/bin/env python3
"""Summarize recorded local timings; no raw incident evidence leaves the host."""
import argparse
import json
import math
import sqlite3
from pathlib import Path
from urllib.parse import quote

FIELDS=('collection_ms','model_queue_ms','model_ms','result_wait_ms','response_ms')


def stats(values,total):
    ordered=sorted(v for v in values if type(v) in (int,float) and math.isfinite(v) and v>=0)
    percentiles={name:round(ordered[math.ceil(len(ordered)*q)-1],2) if ordered else None
                 for name,q in (('p50',.5),('p95',.95),('p99',.99))}
    return {'samples':len(ordered),'missing_or_invalid':total-len(ordered),**percentiles}


def summarize(db,limit=10000):
    if type(limit) is not int or not 1<=limit<=10000:raise ValueError('Limit must be 1–10000')
    rows=db.execute('SELECT '+','.join(FIELDS)+' FROM case_timings ORDER BY rowid DESC LIMIT ?', (limit,)).fetchall()
    steps=db.execute("SELECT result_json FROM response_steps WHERE status='executed' ORDER BY rowid DESC LIMIT ?",(limit,)).fetchall()
    reactions=[]
    for (raw,) in steps:
        try:
            item=json.loads(raw)
            reactions.append(item.get('reaction_ms') if isinstance(item,dict) else None)
        except (ValueError,TypeError):reactions.append(None)
    return {'scope':'Recorded case and executed-step timings, milliseconds; different stages can have different samples. Not an SLA or proof of kernel-to-response latency.',
            'limit_per_table':limit,'case_samples':len(rows),'stages':{name:stats([r[i] for r in rows],len(rows)) for i,name in enumerate(FIELDS)},
            'reaction_from_last_evidence_ms':stats(reactions,len(steps))}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db');parser.add_argument('--limit',type=int,default=10000)
    args=parser.parse_args();uri='file:'+quote(str(Path(args.database).resolve()),safe='/')+'?mode=ro'
    with sqlite3.connect(uri,uri=True,timeout=2) as db:print(json.dumps(summarize(db,args.limit),indent=2))


if __name__=='__main__':main()
