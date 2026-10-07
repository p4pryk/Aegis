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
          'response_steps', 'response_attempts', 'case_timings')
ACTIVE = ('collecting', 'awaiting_analysis', 'recognized')


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
        ids = [r[0] for r in db.execute("SELECT id FROM cases WHERE status NOT IN (?,?,?) AND updated_at<? ORDER BY updated_at LIMIT 100", (*ACTIVE, cutoff))]
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


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description='Export a retained AEGIS case and its evidence')
    parser.add_argument('case_id');parser.add_argument('--output',required=True)
    parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db')
    args=parser.parse_args();export_case(args.database,args.case_id,args.output)
