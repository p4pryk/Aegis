"""Read-only bounded analysis backlog; display eligibility never authorizes execution."""
import sqlite3

def read(conn):
    try:
        counts={r[0]:r[1] for r in conn.execute("SELECT status,count(*) FROM cases WHERE status IN ('collecting','awaiting_analysis') GROUP BY status")}
        rows=[dict(r) for r in conn.execute("""SELECT c.id,c.kind,c.subject,c.version,c.updated_at,q.queued_at,q.boot_id,q.reason,
            json_array_length(c.evidence_json,'$.allowed_actions') AS actions,p.root_id,p.part
            FROM cases c LEFT JOIN analysis_queue q ON q.case_id=c.id AND q.version=c.version
            LEFT JOIN case_parts p ON p.case_id=c.id WHERE c.status='awaiting_analysis'
            ORDER BY coalesce(q.queued_at,c.updated_at),c.id LIMIT 256""")]
        return dict(queue_rows=rows,queue_counts=counts,queue_available=True)
    except sqlite3.OperationalError:
        return dict(queue_rows=[],queue_counts={},queue_available=False)

def lines(data,width,now):
    from console import wrapped
    out=[]
    def add(text,level='neutral'):out.extend(wrapped(text,width,level))
    if not data.get('queue_available'):
        add('Queue data unavailable; this recording may predate queue tracking.','warning');return out
    counts=data.get('queue_counts',{});rows=data.get('queue_rows',[])
    add(f"Collecting: {counts.get('collecting',0)} | Awaiting assessment: {counts.get('awaiting_analysis',0)} | Shown: {len(rows)} / maximum 256")
    add('Read-only / ordered by queue age / timing eligibility is not permission to act.','warning')
    overload=data.get('correlation_overload',{})
    if overload:
        add('ENROLLMENT REFUSED: '+str(overload.get('rejections','at least 1'))+' attempts; last refusal '+str(max(0,int(now-overload.get('time',now))))+'s ago. Some events were not added to cases; this warning is historical.','critical')
    heartbeat=data.get('heartbeat',{});fresh=0<=now-heartbeat.get('time',0)<15
    for row in rows:
        queued=row.get('queued_at');age=max(0,now-queued) if queued is not None else None
        add('-'*width)
        add(row['id']+' / v'+str(row['version'])+' / '+row['kind'])
        add('Subject: '+row['subject'])
        add('Wait: '+(str(int(age))+'s' if age is not None else 'not yet registered')+' | '+(row.get('reason') or 'WAITING FOR QUEUE REGISTRATION'),'warning')
        if row.get('root_id'):add('Chain '+row['root_id']+' / part '+str(row['part']))
        if not fresh or queued is None or not all(k in heartbeat for k in ('boot_id','analysis_window','queue_window')):
            add('Timing unknown: current core heartbeat and queue registration required.','warning');continue
        remaining=max(0,int(heartbeat['queue_window']-age))
        add('Assessment expires in '+str(remaining)+'s; provider retries and budget still apply.')
        if remaining==0:add('QUEUE EXPIRED: awaiting core reconciliation; no automatic response.','warning')
        elif row['boot_id']!=heartbeat['boot_id'] or age>heartbeat['analysis_window']:
            add('HISTORICAL ONLY: automatic response window expired or host rebooted.','warning')
        elif not row.get('actions'):add('REVIEW ONLY: no containment actions in the recorded policy.')
        else:add('Response time window open for '+str(max(0,int(heartbeat['analysis_window']-age)))+'s; model verdict and all executor checks still required.','warning')
    if not rows:add('No cases are currently awaiting assessment.')
    return out
