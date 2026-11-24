#!/usr/bin/env python3
"""Evaluate synthetic cases without executing responses or bypassing model budget."""
import argparse
import hashlib
import json
import math
import os
import pathlib
import re
import time

import agent
import ai_worker

DATASET=pathlib.Path(__file__).resolve().parent/'evaluation'/'cases.json'


def load_cases(path):
    path=pathlib.Path(path)
    if path.stat().st_size>1024*1024:raise ValueError('Evaluation dataset exceeds 1 MiB')
    value=json.loads(path.read_text())
    if not isinstance(value,dict) or value.get('schema')!=1 or not isinstance(value.get('cases'),list) or not 1<=len(value['cases'])<=200:raise ValueError('Invalid evaluation dataset')
    seen=set()
    for case in value['cases']:
        if not isinstance(case,dict) or not isinstance(case.get('id'),str) or not re.fullmatch(r'[a-z0-9-]{1,64}',case['id']) or case['id'] in seen:raise ValueError('Invalid evaluation case ID')
        seen.add(case['id']);evidence=case.get('evidence')
        if case.get('label') not in ('attack','benign','ambiguous') or not isinstance(case.get('kind'),str) or not isinstance(evidence,dict):raise ValueError('Invalid evaluation case')
        events=evidence.get('events');actions=evidence.get('allowed_actions');required=evidence.get('required_evidence_ids')
        if not isinstance(events,list) or len(events)>64 or not isinstance(actions,list) or len(actions)>8 or not all(isinstance(a,dict) for a in actions) or not isinstance(required,list) or not isinstance(evidence.get('policy',{}),dict) or not isinstance(evidence.get('edges',[]),list) or not isinstance(evidence.get('signals',[]),list):raise ValueError('Invalid evaluation evidence bounds')
        ids=[e.get('event_id') for e in events if isinstance(e,dict)]
        if len(ids)!=len(events) or any(not isinstance(i,str) for i in ids) or len(ids)!=len(set(ids)) or not all(isinstance(i,str) and i in ids for i in required):raise ValueError('Invalid evaluation evidence IDs')
        if not isinstance(case.get('forbidden_output',[]),list) or not all(isinstance(x,str) and x for x in case.get('forbidden_output',[])):raise ValueError('Invalid forbidden output marker')
        if len(json.dumps(evidence).encode())>48000:raise ValueError('Evaluation evidence exceeds model limit')
    return value['cases']


def reserve_and_analyze(row,config,deadline,counter=None):
    """Share the worker lock, hourly budget, reserve and cooldown with live traffic."""
    cap,reserve,spacing=ai_worker.limits(config);path=ai_worker.OUT/'correlation-worker-state.json'
    while True:
        if time.monotonic()>=deadline:raise TimeoutError('Evaluation time limit reached')
        with ai_worker.budget_lock():
            if time.monotonic()>=deadline:raise TimeoutError('Evaluation time limit reached')
            now=time.time();state=json.loads(path.read_text()) if path.exists() else {'hour':int(now//3600),'calls':0,'attempts':{}}
            if not isinstance(state,dict) or type(state.get('hour')) is not int or type(state.get('calls')) is not int or state['calls']<0 or not isinstance(state.get('attempts'),dict):raise ValueError('Invalid shared budget state')
            for field in ('last_call_at','unavailable_until'):
                if type(state.get(field,0)) not in (int,float) or not math.isfinite(state.get(field,0)) or state.get(field,0)<0:raise ValueError('Invalid shared budget state')
            if not ai_worker.advance_budget_hour(state,now):raise RuntimeError('Clock moved backwards; model budget remains protected')
            if now<state.get('unavailable_until',0):raise RuntimeError('Model provider is in cooldown')
            if state['calls']>=cap-reserve:raise RuntimeError('Ordinary model budget exhausted; response reserve protected')
            wait=max(0,state.get('last_call_at',0)+spacing-now)
            if not wait:
                state['calls']+=1;state['last_call_at']=now
                ai_worker.write(path,state,durable=True)
                if counter is not None:counter[0]+=1
                try:result=ai_worker.analyze(row,config)
                except Exception as exc:
                    state['unavailable_until']=time.time()+ai_worker.retry_delay(exc)
                    ai_worker.write(path,state,durable=True)
                    raise
                if state.get('unavailable_until',0):
                    state['unavailable_until']=0;ai_worker.write(path,state,durable=True)
                return result
        time.sleep(min(wait,1))


def summary(results,cases):
    scored=[r for r in results if type(r.get('predicted')) is bool and r['label']!='ambiguous'
            and r.get('response_gate') in ('allowed','none') and not r.get('forbidden_marker_seen',False) and not r.get('error')]
    expected=sum(case['label']!='ambiguous' for case in cases)
    invalid=sum(r['label']!='ambiguous' and type(r.get('predicted')) is bool and
                (r.get('response_gate')=='rejected' or r.get('forbidden_marker_seen',False)) for r in results)
    tp=sum(r['label']=='attack' and r['predicted'] is True for r in scored)
    fn=sum(r['label']=='attack' and r['predicted'] is False for r in scored)
    fp=sum(r['label']=='benign' and r['predicted'] is True for r in scored)
    tn=sum(r['label']=='benign' and r['predicted'] is False for r in scored)
    def percentiles(values):
        ordered=sorted(values)
        return {name:ordered[min(len(ordered)-1,math.ceil(len(ordered)*q)-1)] if ordered else None for name,q in (('p50',.5),('p95',.95),('p99',.99))}
    durations=[r['elapsed_ms'] for r in results if r.get('origin')=='model' and r.get('predicted') is not None]
    provider=[r['provider_ms'] for r in results if r.get('origin')=='model' and 'provider_ms' in r and r.get('predicted') is not None]
    return {'scored':len(scored),'expected_non_ambiguous':expected,'score_coverage':round(len(scored)/expected,4) if expected else None,
            'invalid_outputs_excluded':invalid,'not_run':len(cases)-len(results),
            'true_positive':tp,'false_negative':fn,'false_positive':fp,'true_negative':tn,
            'precision':round(tp/(tp+fp),4) if tp+fp else None,'recall':round(tp/(tp+fn),4) if tp+fn else None,
            'false_positive_rate':round(fp/(fp+tn),4) if fp+tn else None,
            'ambiguous':sum(r['label']=='ambiguous' for r in results),'errors':sum(r.get('error') is not None for r in results),
            'policy_rejections':sum(r.get('response_gate')=='rejected' for r in results),
            'forbidden_markers':sum(r.get('forbidden_marker_seen',False) for r in results),
            'model_total_samples':len(durations),'model_provider_samples':len(provider),
            'model_total_ms':percentiles(durations),'model_provider_ms':percentiles(provider)}


def run(cases,config,max_calls,seconds,output):
    if type(max_calls) is not int or not 1<=max_calls<=20:raise ValueError('Evaluation allows 1–20 model calls')
    if type(seconds) is not int or not 10<=seconds<=3600:raise ValueError('Evaluation duration must be 10–3600 seconds')
    ai_worker.model_endpoint(config);ai_worker.limits(config)
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    results=[];calls=[0];deadline=time.monotonic()+seconds;stopped=None
    with os.fdopen(fd,'w') as report:
        try:
            for case in cases:
                if time.monotonic()>=deadline:stopped='Evaluation time limit reached';break
                row={'id':case['id'],'kind':case['kind'],'version':1,'evidence_json':json.dumps(case['evidence'])}
                local=case['evidence'].get('policy',{}).get('actor_authorization')=='approved' and not case['evidence']['allowed_actions']
                if not local and calls[0]>=max_calls:stopped='Evaluation call limit reached';break
                started=time.monotonic();entry={'id':case['id'],'label':case['label'],'origin':'local' if local else 'model'}
                try:
                    if local:result=ai_worker.local_authorized_analysis(row)
                    else:
                        result=reserve_and_analyze(row,config,deadline,calls)
                    analysis=result['analysis'];entry['predicted']=analysis['attack'];entry['confidence']=analysis['confidence']
                    if not local and type(result.get('seconds')) in (int,float) and math.isfinite(result['seconds']) and result['seconds']>=0:entry['provider_ms']=round(result['seconds']*1000,3)
                    entry['summary']=analysis['summary'];entry['uncertainty']=analysis['uncertainty'];entry['next_step']=analysis['next_step']
                    entry['forbidden_marker_seen']=any(marker in json.dumps(analysis) for marker in case.get('forbidden_output',[]))
                    try:
                        validated=agent.CorrelatedEngine.validate_result(object.__new__(agent.CorrelatedEngine),
                            (row['id'],row['version'],row['evidence_json']),result)
                        entry['response_gate']='allowed' if validated['proposed_actions'] else 'none'
                    except (ValueError,TypeError,KeyError):entry['response_gate']='rejected'
                except Exception as exc:
                    entry.update(predicted=None,error=type(exc).__name__);stopped='Model unavailable or budget exhausted'
                entry['elapsed_ms']=round((time.monotonic()-started)*1000,3);results.append(entry)
                print(json.dumps({'case':entry['id'],'label':entry['label'],'predicted':entry['predicted'],'error':entry.get('error')}),flush=True)
                if stopped:break
        finally:
            complete=len(results)==len(cases) and not stopped;counts=summary(results,cases)
            safety_checks_passed=bool(complete and not any(counts[key] for key in ('errors','policy_rejections','forbidden_markers')))
            result={'dataset_sha256':hashlib.sha256(json.dumps(cases,sort_keys=True).encode()).hexdigest(),
                    'scope':'Synthetic known-intent cases; not an estimate of production detection accuracy. No actions executed.',
                    'model_calls_attempted':calls[0],'results':results,'summary':counts,'stopped':stopped,
                    'complete':complete,'safety_checks_passed':safety_checks_passed}
            json.dump(result,report,indent=2);report.flush();os.fsync(report.fileno())
    return result


def main():
    parser=argparse.ArgumentParser(description='Evaluate labelled synthetic evidence without executing defenses')
    parser.add_argument('--dataset',default=str(DATASET));parser.add_argument('--config',default=ai_worker.CONFIG)
    mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--validate',action='store_true');mode.add_argument('--live',action='store_true')
    parser.add_argument('--output');parser.add_argument('--max-calls',type=int,default=20);parser.add_argument('--seconds',type=int,default=600)
    args=parser.parse_args();cases=load_cases(args.dataset)
    if args.validate:
        print(json.dumps({'cases':len(cases),'labels':{label:sum(case['label']==label for case in cases) for label in ('attack','benign','ambiguous')},'network_calls':0}));return
    if not args.output:parser.error('--live requires --output')
    config=json.loads(pathlib.Path(args.config).read_text());result=run(cases,config,args.max_calls,args.seconds,args.output)
    print(json.dumps({'complete':result['complete'],'safety_checks_passed':result['safety_checks_passed'],'summary':result['summary'],'model_calls_attempted':result['model_calls_attempted']}))
    if not result['complete'] or not result['safety_checks_passed']:raise SystemExit(1)


if __name__=='__main__':main()
