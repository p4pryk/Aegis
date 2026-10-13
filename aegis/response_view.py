"""Read-only response history, with a deliberately small public receipt schema."""
import datetime, json, os, pathlib, re, stat

LIMIT = 200

def timestamp(value):
    try:return datetime.datetime.fromtimestamp(float(value)).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError,ValueError,OverflowError,OSError):return 'time unavailable'


def public_receipt(receipt):
    history=receipt.get('history',[])
    last=history[-1] if history else {}
    # No before/after snapshots, account fingerprints, tokens or administrator reasons.
    return {k:v for k,v in dict(id=receipt['id'],time=receipt.get('time',0),action=receipt['action'],
        target=receipt.get('target') if receipt['action'] in ('block_ip','quarantine_account','quarantine_persistence') else None,
        state=receipt['state'],eligible=bool(receipt.get('eligible')),last_state=last.get('state'),
        updated_at=last.get('completed_at',last.get('time',receipt.get('time',0))),
        error=re.sub(r'\b[0-9a-f]{32,}\b','[redacted]',str(last.get('error','')),flags=re.I)[:300]).items()}

def read_receipts(database):
    root=pathlib.Path(database).parent/'response-history'
    try:
        info=root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('Unsafe history directory')
        with os.scandir(root) as entries:
            paths=[pathlib.Path(entry.path) for entry in entries if re.fullmatch(r'[a-f0-9]{32}\.json',entry.name)]
        paths.sort(key=lambda p:p.lstat().st_mtime,reverse=True)
        rows=[]
        for path in paths[:LIMIT]:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
            with os.fdopen(fd) as stream:
                info=os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>4096:raise ValueError('Unsafe history record')
                value=json.loads(stream.read(4097))
                if not isinstance(value,dict) or not all(k in value for k in ('id','time','action','state')):raise ValueError('Invalid public receipt')
                rows.append(value)
        return {'responses':rows,'response_history_status':'AVAILABLE','response_history_more':len(paths)>LIMIT}
    except (OSError,ValueError,TypeError,KeyError):
        return {'responses':[],'response_history_status':'UNAVAILABLE'}

def history_lines(data,width,review=False):
    from console import wrapped,decoded,stamp
    lines=[]
    status=data.get('response_history_status','UNAVAILABLE')
    if status!='AVAILABLE':lines+=wrapped('[!] Response receipt history unavailable. Check the executor and viewer permissions.',width,'warning')
    if data.get('response_history_more'):lines+=wrapped('[!] Showing the latest 200 receipts; older records remain in the root rollback ledger.',width,'warning')
    if review and data.get('review_more'):lines+=wrapped('[!] Showing the latest 200 failed cases; older cases remain in the database.',width,'warning')
    rows=sorted(data.get('responses',[]),key=lambda r:r.get('updated_at',r.get('time',0)),reverse=True)
    count=0
    for row in rows:
        state=row.get('state');refused=row.get('last_state')=='refused' and state!='restored'
        needs=state in ('prepared','forward_uncertain','undo_running','undo_uncertain') or refused
        if review and not needs:continue
        count+=1
        label='REVIEW REQUIRED' if needs else 'RESTORED' if state=='restored' else 'CONTAINED' if state=='contained' else 'UNKNOWN'
        level='critical' if needs else 'defended'
        lines+=wrapped(f"{'[!]' if needs else '[<>]'} {timestamp(row.get('updated_at',row.get('time')))} [{label}] {row.get('action')} / {row.get('target') or 'restricted target'}",width,level)
        lines+=wrapped('Receipt: '+str(row.get('id')),width)
        linked=[s.get('case_id') for s in data.get('response_steps',[]) if (decoded(s.get('result_json'),{}) or {}).get('undo_receipt')==row.get('id')]
        if linked:lines+=wrapped('Case: '+str(linked[0]),width)
        lines+=wrapped('Recorded state: '+str(state)+(' / rollback refused' if refused else ''),width,level)
        if needs:
            lines+=wrapped('Reason: '+(row.get('error') or 'Operation was not conclusively completed.'),width,'warning')
            lines+=wrapped('Next: inspect the receipt and current host state as root; do not retry blindly.',width)
        else:lines+=wrapped('Rollback: '+('plan required; eligibility is rechecked' if row.get('eligible') and state=='contained' else 'completed' if state=='restored' else 'not available'),width)
        lines.append('-'*width)
    if review:
        for case in data.get('review_cases',[]):
            count+=1
            evidence=decoded(case.get('evidence_json'),{}) or {}
            detail=decoded(case.get('review_details'),{}) or {}
            lines+=wrapped('[!] '+timestamp(case.get('updated_at'))+' ['+str(case.get('status','')).upper()+'] Case: '+str(case.get('id')),width,'critical')
            lines+=wrapped('Evidence: '+str(len(evidence.get('events',[])))+' events / '+str(len(evidence.get('edges',[])))+' links',width)
            reason=detail.get('error') or 'Response incomplete; inspect the recorded attempts and incident chain.'
            lines+=wrapped('Reason: '+re.sub(r'\b[0-9a-f]{32,}\b','[redacted]',str(reason),flags=re.I),width,'warning')
            lines+=wrapped('Next: open the incident with --case '+str(case.get('id'))+'; verify evidence and worker health before intervening.',width)
            lines.append('-'*width)
    if not review:
        for step in data.get('response_steps',[]):
            action=decoded(step.get('action_json'),{}) or {};result=decoded(step.get('result_json'),{}) or {}
            count+=1
            state=step.get('status','unknown');level='defended' if state=='executed' else 'critical' if state=='failed' else 'warning'
            lines+=wrapped(f"[i] Case: {step.get('case_id')} / {action.get('action','unknown')} / {state.upper()} / attempts: {step.get('attempts',0)}",width,level)
            lines+=wrapped('Receipt: '+str(result.get('undo_receipt','legacy or unavailable; inspect incident chain')),width)
            lines.append('-'*width)
        if data.get('response_steps_more'):lines+=wrapped('[!] Latest 200 response steps shown; older attempts remain in the database.',width,'warning')
    if not count:lines+=wrapped('No review items in the loaded records.' if review else 'No response receipts recorded.',width)
    lines+=wrapped('Read-only / recorded outcomes, not a live host-state check. IP expiry is not inferred. Rollback remains a separate root-only command.',width)
    return lines
