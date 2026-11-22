"""Durable, bounded response attempts. Only a freshly checked local plan is enrolled."""
import hashlib
import json
import pathlib
import re
import sqlite3
import time


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def policy_hash(config):
    return hashlib.sha256(encode(config).encode()).hexdigest()


def authorize_step(config, envelope):
    """Resolve a committed intent at the privileged boundary; never accept caller actions."""
    from policy import require_enforce
    from agent import CorrelatedEngine, safe_ip
    require_enforce(config)
    if not isinstance(envelope,dict) or set(envelope)!={'case_id','position','version'}:
        raise ValueError('A committed case step is required')
    identifier,position,version=envelope['case_id'],envelope['position'],envelope['version']
    if not isinstance(identifier,str) or not re.fullmatch(r'[a-f0-9]{24}',identifier) or type(position) is not int or position<0 or type(version) is not int or version<1:
        raise ValueError('Invalid case step')
    path=pathlib.Path(config['data_dir'])/'incidents.db'
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=3)
    try:
        db.execute('BEGIN')
        row=db.execute('''SELECT c.version,c.status,c.kind,c.evidence_json,r.boot_id,r.policy_hash,r.deadline,
                                 s.action_json,s.request_json,s.status,c.subject,c.analysis_json
                          FROM cases c JOIN response_runs r ON r.case_id=c.id
                          JOIN response_steps s ON s.case_id=c.id
                          WHERE c.id=? AND s.position=?''',(identifier,position)).fetchone()
        if not row:raise ValueError('Unknown case step')
        current_boot=pathlib.Path('/proc/sys/kernel/random/boot_id')
        boot=current_boot.read_text().strip() if current_boot.exists() else 'test-boot'
        if row[0]!=version or row[1]!='recognized' or row[4]!=boot or row[5]!=policy_hash(config) or time.time()>row[6] or row[9]!='running':
            raise ValueError('Case step expired or authorization changed')
        evidence=json.loads(row[3]);action=json.loads(row[7]);request=json.loads(row[8])
        if evidence.get('version')!=version or position>=len(evidence.get('allowed_actions',[])) or evidence['allowed_actions'][position]!=action:
            raise ValueError('Action differs from recorded evidence')
        assessment=json.loads(row[11]);confidence=assessment.get('confidence')
        references=assessment.get('evidence_ids')
        if (assessment.get('attack') is not True or type(confidence) not in (int,float) or
            not evidence.get('policy',{}).get('minimum_confidence',.85)<=confidence<=1 or
            assessment.get('proposed_actions')!=evidence['allowed_actions'] or not isinstance(references,list) or
            not set(evidence.get('required_evidence_ids',[])).issubset(references)):
            raise ValueError('Assessment does not authorize this response')
        if not isinstance(request,dict) or any(request.get(k)!=v for k,v in action.items()):
            raise ValueError('Request differs from authorized action')
        extra=set(request)-set(action)
        permitted={'quarantine_account':{'expected_uid'},'block_ip':{'expires_at'}}.get(action.get('action'),set())
        if extra!=permitted:raise ValueError('Invalid action fields')
        if action.get('action')=='quarantine_account':
            account=next((e for e in evidence.get('events',[]) if e.get('kind')=='account_created' and e.get('subject')==action.get('user')),None)
            if not account or request.get('expected_uid')!=account.get('details',{}).get('account_uid'):
                raise ValueError('Account identity differs from evidence')
        if position==0:
            # Recompute the local chain at the privileged boundary before any effect.
            checker=object.__new__(CorrelatedEngine);checker.c=config;checker.db=db;checker.boot_id=boot
            fresh=checker.snapshot(identifier,row[2],row[10],version)
            if fresh['allowed_actions']!=evidence.get('allowed_actions') or fresh['required_evidence_ids']!=evidence.get('required_evidence_ids'):
                raise ValueError('Current evidence no longer supports this response')
        previous=[r[0] for r in db.execute('SELECT status FROM response_steps WHERE case_id=? AND position<? ORDER BY position',(identifier,position))]
        if len(previous)!=position or (action.get('action')=='block_ip' and any(s!='executed' for s in previous)):
            raise ValueError('Prior containment not verified')
        if action.get('action')=='block_ip':
            scope='ssh_dedicated_source_ips' if row[2]=='ssh_session_account' else 'app_dedicated_source_ips' if row[2] in ('app_sql_account','app_sql_persistence') else None
            if not scope or request.get('ip') not in config.get(scope,[]) or not safe_ip(request.get('ip'),config):
                raise ValueError('IP is outside dedicated response scope')
        return request
    finally:db.close()


def initialize(db):
    db.executescript('''
        CREATE TABLE IF NOT EXISTS case_timings(case_id TEXT PRIMARY KEY, collection_ms REAL, model_queue_ms REAL, model_ms REAL, result_wait_ms REAL, response_ms REAL);
        CREATE TABLE IF NOT EXISTS case_versions (
            case_id TEXT, version INTEGER, archived_at REAL, status TEXT,
            evidence_json TEXT, analysis_json TEXT, result_json TEXT,
            PRIMARY KEY(case_id, version));
        CREATE TABLE IF NOT EXISTS response_runs (
            case_id TEXT PRIMARY KEY, boot_id TEXT, policy_hash TEXT, deadline REAL);
        CREATE TABLE IF NOT EXISTS response_steps (
            case_id TEXT, position INTEGER, action_json TEXT, request_json TEXT,
            status TEXT, attempts INTEGER, next_attempt REAL, result_json TEXT,
            PRIMARY KEY(case_id, position));
        CREATE TABLE IF NOT EXISTS response_attempts (
            case_id TEXT, position INTEGER, attempt INTEGER, started_at REAL,
            completed_at REAL, result_json TEXT, PRIMARY KEY(case_id, position, attempt));
    ''')
    db.commit()


def archive(db, identifier):
    db.execute('''INSERT OR IGNORE INTO case_versions
        SELECT id,version,?,status,evidence_json,analysis_json,result_json
        FROM cases WHERE id=? AND (analysis_json!='{}' OR result_json!='{}')''',
        (time.time(), identifier))


def prepare(engine, identifier, data):
    """Caller commits this plan atomically with the recognized assessment."""
    from policy import require_enforce
    require_enforce(engine.c)
    now = time.time()
    engine.db.execute('INSERT INTO response_runs VALUES (?,?,?,?)',
                      (identifier, engine.boot_id, policy_hash(engine.c), now + 120))
    for position, action in enumerate(data['allowed_actions']):
        request = dict(action)
        if action['action'] == 'quarantine_account':
            account = next(e for e in data['events']
                           if e['kind'] == 'account_created' and e['subject'] == action['user'])
            request['expected_uid'] = account['details']['account_uid']
        elif action['action'] == 'block_ip':
            # Retries must not refresh an incident's original block lifetime.
            request['expires_at'] = now + int(engine.c['block_seconds'])
        engine.db.execute('INSERT INTO response_steps VALUES (?,?,?,?,?,?,?,?)',
                          (identifier, position, encode(action), encode(request),
                           'pending', 0, 0, '{}'))


def publish(engine, identifier):
    rows = engine.db.execute('SELECT action_json,status,result_json FROM response_steps '
                             'WHERE case_id=? ORDER BY position', (identifier,)).fetchall()
    results = []
    for raw, status, result in rows:
        item = {'action': json.loads(raw), 'status': status}
        detail = json.loads(result)
        if status == 'executed':
            item['result'] = detail
        elif detail:
            item['error'] = detail.get('error', 'Response pending verification')
        results.append(item)
    engine.db.execute('UPDATE cases SET result_json=? WHERE id=?', (encode(results), identifier))
    engine.db.commit()


def advance(engine, identifier, now=None, stop=None):
    now = time.time() if now is None else now
    run = engine.db.execute('SELECT boot_id,policy_hash,deadline FROM response_runs WHERE case_id=?',
                            (identifier,)).fetchone()
    if not run:
        # Old versions never saved a safe execution plan: do not guess what ran.
        engine.status(identifier, 'defense_error', {'error': 'Interrupted legacy response needs manual review'})
        archive(engine.db, identifier)
        engine.db.commit()
        return
    valid = engine.c.get('response_mode','observe') == 'enforce' and run[0] == engine.boot_id and run[1] == policy_hash(engine.c) and now <= run[2]
    steps = engine.db.execute('SELECT position,action_json,request_json,status,attempts,next_attempt '
                              'FROM response_steps WHERE case_id=? ORDER BY position', (identifier,)).fetchall()
    for position, raw, request, status, attempts, next_attempt in steps:
        if stop is not None and stop.is_set():break
        if status in ('executed', 'failed'):
            continue
        if not valid or time.time() > run[2]:
            engine.db.execute("UPDATE response_steps SET status='failed',result_json=? WHERE case_id=? AND position=?",
                              (encode({'error': 'Recovery expired, boot changed or policy changed; manual review required'}), identifier, position))
            continue
        if next_attempt > now:
            continue
        action = json.loads(raw)
        if action['action'] == 'block_ip':
            previous = [r[0] for r in engine.db.execute('SELECT status FROM response_steps WHERE case_id=? AND position<?',
                                                        (identifier, position))]
            if any(s == 'failed' for s in previous):
                engine.db.execute("UPDATE response_steps SET status='failed',result_json=? WHERE case_id=? AND position=?",
                                  (encode({'error': 'IP block withheld: preceding containment was not verified'}), identifier, position))
                continue
            if any(s != 'executed' for s in previous):
                continue
        if attempts >= 3:
            engine.db.execute("UPDATE response_steps SET status='failed',result_json=? WHERE case_id=? AND position=?",
                              (encode({'error': 'Attempt limit reached; last outcome may be unknown; manual review required'}), identifier, position))
            continue
        attempt = attempts + 1
        engine.db.execute("UPDATE response_steps SET status='running',attempts=? WHERE case_id=? AND position=?",
                          (attempt, identifier, position))
        engine.db.execute('INSERT INTO response_attempts VALUES (?,?,?,?,NULL,NULL)',
                          (identifier, position, attempt, time.time()))
        publish(engine, identifier)  # Durable intent BEFORE the external side effect.
        started = time.monotonic()
        try:
            if hasattr(engine,'execute_step'):
                version=engine.db.execute('SELECT version FROM cases WHERE id=?',(identifier,)).fetchone()[0]
                out=engine.execute_step(identifier,position,version)
            else:out = engine.execute(json.loads(request))
            if not isinstance(out, dict) or out.get('verified') is not True:
                raise RuntimeError('Executor did not verify action')
            out.update(executed_at=time.time(), execution_ms=round((time.monotonic()-started)*1000, 3))
            evidence = json.loads(engine.db.execute('SELECT evidence_json FROM cases WHERE id=?', (identifier,)).fetchone()[0])
            out['reaction_ms'] = round((out['executed_at'] - max(e['event_time'] for e in evidence['events'])) * 1000, 3)
            state = 'executed'
            if action['action'] == 'terminate_session':
                engine.db.execute('UPDATE ssh_sessions SET active=0 WHERE identity=?',
                                  (f"{action['boot_id']}:{action['session']}:{action['auid']}",))
        except Exception as exc:
            out = {'error': str(exc)[:500]}
            state = 'failed' if attempt >= 3 else 'pending'
        engine.db.execute('UPDATE response_steps SET status=?,next_attempt=?,result_json=? WHERE case_id=? AND position=?',
                          (state, now + 5 * 2 ** (attempt-1), encode(out), identifier, position))
        engine.db.execute('UPDATE response_attempts SET completed_at=?,result_json=? WHERE case_id=? AND position=? AND attempt=?',
                          (time.time(), encode(out), identifier, position, attempt))
        publish(engine, identifier)
    publish(engine, identifier)
    states = [r[0] for r in engine.db.execute('SELECT status FROM response_steps WHERE case_id=?', (identifier,))]
    if states and all(s in ('executed', 'failed') for s in states):
        engine.db.execute('UPDATE case_timings SET response_ms=? WHERE case_id=?', ((time.time()-(run[2]-120))*1000,identifier))
        engine.status(identifier, 'defended' if all(s == 'executed' for s in states) else 'defense_error')
        archive(engine.db, identifier)
        engine.db.commit()


def resume(engine, now, stop=None):
    for identifier, in engine.db.execute("SELECT id FROM cases WHERE status='recognized' ORDER BY created_at LIMIT 256").fetchall():
        if stop is not None and stop.is_set():break
        advance(engine, identifier, now, stop=stop)


def main():
    import argparse
    import fcntl
    import pathlib
    from agent import Store, CorrelatedEngine, load_config, request_executor, shutdown_flag
    from maintenance import maintain
    parser=argparse.ArgumentParser();parser.add_argument('--config',default='/etc/defense-agent/config.json');args=parser.parse_args()
    config=load_config(args.config)
    stop=shutdown_flag()
    # One durable queue owner across restarts; never hold a SQLite lock during side effects.
    with (pathlib.Path(config['data_dir'])/'response.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        store=Store(config)
        engine=CorrelatedEngine(config,store,lambda request:request_executor(engine.c,request))
        engine.execute_step=lambda identifier,position,version:request_executor(engine.c,{'case_id':identifier,'position':position,'version':version})
        last_maintenance=0
        try:
            while not stop.is_set():
                engine.c=load_config(args.config)
                store.state('response_worker',{'time':time.time(),'status':'processing'})
                resume(engine,time.time(),stop)
                if not stop.is_set() and time.time()-last_maintenance>=60:
                    maintain(engine)
                    last_maintenance=time.time()
                store.state('response_worker',{'time':time.time(),'status':'stopped' if stop.is_set() else 'idle'})
                if not stop.is_set():time.sleep(.5)
        finally:
            store.db.close()


if __name__=='__main__':main()
