"""Bounded retention of terminal cases and stale model output; explicit case export."""
import argparse
import fcntl
import json
import os
import pathlib
import re
import sqlite3
import stat
import time

TABLES = ('case_events', 'case_status_history', 'case_versions', 'response_runs',
          'response_steps', 'response_attempts', 'case_timings', 'case_parts', 'analysis_queue')
ACTIVE = ('collecting', 'awaiting_analysis', 'recognized')
REVIEW = ('review_required', 'analysis_error', 'defense_error')


def operator_identity():
    sudo_uid=os.environ.get('SUDO_UID','')
    return {'uid':os.getuid(),'effective_uid':os.geteuid(),
            'sudo_uid':int(sudo_uid) if re.fullmatch(r'[0-9]{1,10}',sudo_uid) else None}


def storage(db):
    page = db.execute('PRAGMA page_size').fetchone()[0]
    total = db.execute('PRAGMA page_count').fetchone()[0]
    free = db.execute('PRAGMA freelist_count').fetchone()[0]
    return {'database_bytes': page*total, 'database_used_bytes': page*(total-free)}


def rotate_consumed_app_log(engine):
    path = engine.c.get('application_log', '/var/log/defense-agent/application.jsonl')
    try:
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    except FileNotFoundError:
        return False
    with os.fdopen(fd, 'r+') as file:
        fcntl.flock(file, fcntl.LOCK_EX)
        info = os.fstat(file.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted application log')
        if info.st_size < engine.c.get('application_log_max_bytes', 16*1024*1024):
            return False
        with engine.store.atomic():
            offset = engine.store.state('app_offset') or {}
            if offset.get('ino') != info.st_ino or offset.get('offset') != info.st_size:
                return False  # Never discard unread telemetry to meet a size target.
            file.truncate(0)
            file.flush()
            os.fsync(file.fileno())
            engine.store.state('app_offset', {'ino': info.st_ino, 'offset': 0})
        return True


def maintain(engine, now=None):
    now = time.time() if now is None else now
    db = engine.db
    keep = max(600, float(engine.c.get('retention_days', 7))*86400)
    target = int(engine.c.get('database_retention_bytes', 128*1024*1024))
    before = storage(db)
    # Bounded deletion; only completed cases older than the correlation window qualify.
    cutoff = now-600 if before['database_used_bytes'] > target else now-keep
    with engine.store.atomic():
        protected = ACTIVE + REVIEW
        placeholders = ','.join('?' for _ in protected)
        ids = [r[0] for r in db.execute(f"SELECT id FROM cases WHERE status NOT IN ({placeholders}) AND updated_at<? ORDER BY updated_at LIMIT 100", (*protected, cutoff))]
        for identifier in ids:
            for table in TABLES:
                db.execute('DELETE FROM '+table+' WHERE case_id=?', (identifier,))
            db.execute('DELETE FROM cases WHERE id=?', (identifier,))
    removed_files = 0
    directory = pathlib.Path(engine.c.get('ai_results_dir', '/var/lib/defense-agent-ai'))
    file_bytes = 0
    for path in directory.glob('*'):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            continue
        file_bytes += info.st_size
        match = re.fullmatch(r'([a-f0-9]{24})-v(\d+)\.(?:json|tmp)', path.name)
        if not match or removed_files >= 500 or info.st_mtime > now-600:
            continue
        case = db.execute('SELECT version,status FROM cases WHERE id=?', (match[1],)).fetchone()
        if not case or int(match[2]) != case[0] or case[1] not in ACTIVE:
            path.unlink(missing_ok=True)
            file_bytes -= info.st_size
            removed_files += 1
    db.execute('PRAGMA incremental_vacuum(128)')
    db.commit()
    app_rotated = rotate_consumed_app_log(engine)
    state = dict(storage(db), time=now, deleted_cases=len(ids), deleted_model_files=removed_files,
                 model_output_bytes=file_bytes, application_log_rotated=app_rotated,
                 target_bytes=target, maximum_bytes=int(engine.c.get('database_max_bytes',256*1024*1024)),
                 free_disk_bytes=__import__('shutil').disk_usage(engine.c['data_dir']).free)
    app_path=pathlib.Path(engine.c.get('application_log','/var/log/defense-agent/application.jsonl'))
    state['application_log_bytes']=app_path.stat().st_size if app_path.exists() else 0
    state['pressure'] = (state['application_log_bytes'] > engine.c.get('application_log_max_bytes',16*1024*1024)) or (state['database_used_bytes'] > target or file_bytes > int(engine.c.get('model_output_max_bytes',32*1024*1024)) or state['free_disk_bytes'] < 128*1024*1024)
    engine.store.state('storage_health', state)
    return state


def export_case(database, identifier, output):
    db = sqlite3.connect(pathlib.Path(database).resolve().as_uri()+'?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    try:
        db.execute('BEGIN')
        case = db.execute('SELECT * FROM cases WHERE id=?', (identifier,)).fetchone()
        if case is None:
            raise ValueError('Case not found (it may have expired under retention policy)')
        result = {'exported_at': time.time(), 'case': dict(case)}
        for table in TABLES:
            result[table] = [dict(r) for r in db.execute('SELECT * FROM '+table+' WHERE case_id=?', (identifier,))]
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as file:
            json.dump(result, file, indent=2)
            file.flush();os.fsync(file.fileno())
    finally:
        db.close()


def resolve_review(database, identifier, version, reason):
    """Record an operator's review; this does not execute or undo a response."""
    if os.geteuid() != 0: raise PermissionError('Run as root')
    if not re.fullmatch(r'[a-f0-9]{24}', identifier) or type(version) is not int or version < 1:
        raise ValueError('Invalid case ID or version')
    if not isinstance(reason, str) or not 1 <= len(reason.strip()) <= 500:
        raise ValueError('A reason of 1–500 characters is required')
    db = sqlite3.connect(pathlib.Path(database).resolve().as_uri()+'?mode=rw', uri=True)
    try:
        db.execute('BEGIN IMMEDIATE')
        case = db.execute('SELECT version,status FROM cases WHERE id=?', (identifier,)).fetchone()
        if not case or case[0] != version or case[1] not in REVIEW:
            raise ValueError('Case or version changed, or no review is pending')
        if db.execute("SELECT 1 FROM response_steps WHERE case_id=? AND status IN ('pending','running')", (identifier,)).fetchone():
            raise ValueError('Response is still pending; inspect it before closing the review')
        now = time.time()
        details = {'reason': reason.strip(), 'version': version, 'previous_status': case[1],**operator_identity()}
        db.execute("UPDATE cases SET status='review_closed',updated_at=? WHERE id=?", (now, identifier))
        db.execute('INSERT INTO case_status_history VALUES (?,?,?,?)',
                   (identifier, 'review_closed', now, json.dumps(details)))
        db.commit()
    finally:
        db.close()


def acknowledge_audit_parse(database, expected_count, reason):
    """Record review of a specific audit gap without pretending to recover records."""
    from monitoring import audit_parse_counts
    if os.geteuid()!=0:raise PermissionError('Run as root')
    if type(expected_count) is not int or expected_count<1:raise ValueError('Invalid expected count')
    if not isinstance(reason,str) or not 1<=len(reason.strip())<=500:raise ValueError('A reason of 1–500 characters is required')
    db=sqlite3.connect(pathlib.Path(database).resolve().as_uri()+'?mode=rw',uri=True,timeout=10)
    try:
        db.execute('BEGIN IMMEDIATE')
        values={key:json.loads(value) for key,value in db.execute("SELECT key,value FROM state WHERE key IN ('audit_parse_error','audit_parse_ack')")}
        gap=values.get('audit_parse_error');total,_,unresolved=audit_parse_counts(gap,values.get('audit_parse_ack'))
        if total!=expected_count or not unresolved:raise ValueError('Audit gap changed or is already reviewed; inspect current source health')
        if not isinstance(gap,dict):raise ValueError('Invalid audit gap; manual investigation required')
        now=time.time()
        entry={'time':now,'count':total,'reason':reason.strip(),**operator_identity(),
               'gap_time':gap.get('time'),'last_record_id':gap.get('last_record_id')}
        db.execute('CREATE TABLE IF NOT EXISTS audit_gap_reviews(time REAL,count INTEGER,details_json TEXT)')
        db.execute('INSERT INTO audit_gap_reviews VALUES (?,?,?)',(now,total,json.dumps(entry)))
        db.execute("INSERT OR REPLACE INTO state VALUES ('audit_parse_ack',?)",(json.dumps(entry),))
        db.commit()
    finally:db.close()


def audit_gap_history(database):
    db=sqlite3.connect(pathlib.Path(database).resolve().as_uri()+'?mode=ro',uri=True,timeout=10)
    try:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_gap_reviews'").fetchone():return []
        return [json.loads(row[0]) for row in db.execute('SELECT details_json FROM audit_gap_reviews ORDER BY rowid DESC LIMIT 100')]
    finally:db.close()


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description='Export a case, record a review, or inspect audit gap history')
    parser.add_argument('case_id',nargs='?');parser.add_argument('--output')
    parser.add_argument('--resolve-review',action='store_true');parser.add_argument('--version',type=int);parser.add_argument('--reason')
    parser.add_argument('--ack-audit-parse',type=int,metavar='COUNT');parser.add_argument('--audit-gap-history',action='store_true')
    parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db')
    args=parser.parse_args()
    if args.resolve_review and args.case_id and not args.output and args.version is not None and args.reason and args.ack_audit_parse is None and not args.audit_gap_history:
        resolve_review(args.database,args.case_id,args.version,args.reason);print('Review recorded; no response or rollback was performed.')
    elif args.output and args.case_id and not args.resolve_review and args.version is None and args.reason is None and args.ack_audit_parse is None and not args.audit_gap_history:
        export_case(args.database,args.case_id,args.output)
    elif args.ack_audit_parse is not None and args.reason and not args.case_id and not args.output and not args.resolve_review and args.version is None and not args.audit_gap_history:
        acknowledge_audit_parse(args.database,args.ack_audit_parse,args.reason);print('Audit gap review recorded; lost records were not recovered.')
    elif args.audit_gap_history and not args.case_id and not args.output and not args.resolve_review and args.version is None and args.reason is None and args.ack_audit_parse is None:
        print(json.dumps(audit_gap_history(args.database),indent=2))
    else:parser.error('Use CASE_ID --output PATH; CASE_ID --resolve-review --version N --reason TEXT; --ack-audit-parse COUNT --reason TEXT; or --audit-gap-history')
