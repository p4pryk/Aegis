"""Durable, bounded response attempts. Only a freshly checked local plan is enrolled."""
import hashlib
import json
import time


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def policy_hash(config):
    return hashlib.sha256(encode(config).encode()).hexdigest()


def initialize(db):
    db.executescript('''
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


def advance(engine, identifier, now=None):
    now = time.time() if now is None else now
    run = engine.db.execute('SELECT boot_id,policy_hash,deadline FROM response_runs WHERE case_id=?',
                            (identifier,)).fetchone()
    if not run:
        # Old versions never saved a safe execution plan: do not guess what ran.
        engine.status(identifier, 'defense_error', {'error': 'Interrupted legacy response needs manual review'})
        archive(engine.db, identifier)
        engine.db.commit()
        return
    valid = run[0] == engine.boot_id and run[1] == policy_hash(engine.c) and now <= run[2]
    steps = engine.db.execute('SELECT position,action_json,request_json,status,attempts,next_attempt '
                              'FROM response_steps WHERE case_id=? ORDER BY position', (identifier,)).fetchall()
    for position, raw, request, status, attempts, next_attempt in steps:
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
            out = engine.execute(json.loads(request))
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
        engine.status(identifier, 'defended' if all(s == 'executed' for s in states) else 'defense_error')
        archive(engine.db, identifier)
        engine.db.commit()


def resume(engine, now):
    for identifier, in engine.db.execute("SELECT id FROM cases WHERE status='recognized'").fetchall():
        advance(engine, identifier, now)
