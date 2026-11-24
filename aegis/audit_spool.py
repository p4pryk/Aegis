"""Root-private, bounded audit inbox; acknowledgment follows the core transaction."""
import copy
import json
import os
import pathlib
import re
import select
import sqlite3
import stat
import time
import uuid


def selected(line):
    return bool(re.search(r'^(?:node=\S+ )?type=(?:USER_CHAUTHTOK|1108|GRP_CHAUTHTOK|1133|CHUSER_ID|1125|ACCT_LOCK|1135|ACCT_UNLOCK|1136|USER_MGMT|1102|GRP_MGMT|1132|ADD_GROUP|1116|DEL_GROUP|1117|CHGRP_ID|1119|DEL_USER|1115|CWD|1307|ADD_USER|1114|SYSCALL|1300|PATH|1302|EOE|1320|USER_LOGIN|1112|USER_START|1105|USER_END|1106)\s', line)) and (
        not re.search(r'type=(?:SYSCALL|1300)\s', line) or
        bool(re.search(r'\bkey="?(?:lab_root_exec|aegis_app_exec|aegis_session_exec|aegis_persistence|aegis_identity)"?(?:\s|$)', line)))


class Spool:
    def __init__(self, config):
        self.limit = int(config.get('audit_spool_bytes', 16*1024*1024))
        self.row_limit = int(config.get('audit_spool_records', 50000))
        self.path = pathlib.Path(config.get('audit_spool_dir', '/var/lib/defense-agent-audit')) / 'inbox.db'
        self.loss_marker = pathlib.Path(config.get('runtime_dir', '/run/defense-agent')) / 'audit-loss.pending'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA max_page_count=16384')  # 64 MiB at the default 4 KiB page size.
        self.db.executescript('''CREATE TABLE IF NOT EXISTS inbox(
            id INTEGER PRIMARY KEY AUTOINCREMENT, received REAL, boot TEXT, line TEXT, snapshots TEXT, bytes INTEGER);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value);
            INSERT OR IGNORE INTO meta VALUES ('bytes',0),('rows',0),('accepted',0),('dropped',0),('stream_gaps',0),('stream_reviewed',0);''')
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('identity',?)", (uuid.uuid4().hex,))
        self.db.commit()
        os.chmod(self.path, 0o600)
        self.identity = self.db.execute("SELECT value FROM meta WHERE key='identity'").fetchone()[0]

    def append(self, line, boot, snapshots=None):
        return self.append_batch([(line,boot,snapshots or {})])[0]

    def append_batch(self, entries):
        accepted=[]
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            meta=dict(self.db.execute('SELECT key,value FROM meta'))
            for line,boot,snapshots in entries:
                payload=json.dumps(snapshots)
                size=len(line.encode())+len(payload.encode())
                if size>65536 or meta['bytes']+size>self.limit or meta['rows']>=self.row_limit:
                    meta['dropped']+=1;accepted.append(False);continue
                self.db.execute('INSERT INTO inbox(received,boot,line,snapshots,bytes) VALUES (?,?,?,?,?)',
                                (time.time(),boot,line,payload,size))
                meta['bytes']+=size;meta['rows']+=1;meta['accepted']+=1;accepted.append(True)
                self.db.execute("INSERT OR REPLACE INTO meta VALUES ('last_received_at',?)",(time.time(),))
            for key in ('bytes','rows','accepted','dropped'):
                self.db.execute('UPDATE meta SET value=? WHERE key=?',(meta[key],key))
        return accepted

    def record_stream_gap(self):
        # Record a possible gap without storing or interpreting partial data.
        with self.db:
            self.db.execute("UPDATE meta SET value=value+1 WHERE key='stream_gaps'")

    def batch(self, cursor, limit=100):
        return self.db.execute('SELECT id,received,boot,line,snapshots FROM inbox WHERE id>? ORDER BY id LIMIT ?',
                               (cursor, limit)).fetchall()

    def acknowledge(self, cursor):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            count, size = self.db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM inbox WHERE id<=?', (cursor,)).fetchone()
            if count:
                self.db.execute('DELETE FROM inbox WHERE id<=?', (cursor,))
                self.db.execute("UPDATE meta SET value=value-? WHERE key='bytes'", (size,))
                self.db.execute("UPDATE meta SET value=value-? WHERE key='rows'", (count,))

    def health(self):
        meta = dict(self.db.execute('SELECT key,value FROM meta'))
        oldest = self.db.execute('SELECT received FROM inbox ORDER BY id LIMIT 1').fetchone()
        return {**meta, 'io_error_pending':os.path.lexists(self.loss_marker), 'limit_bytes': self.limit, 'oldest_seconds': max(0, time.time()-oldest[0]) if oldest else 0,
                'file_bytes': self.path.stat().st_size, 'pressure': meta['bytes'] >= .8*self.limit or meta['rows'] >= .8*self.row_limit}


def mark_io_loss(path):
    """Expose a pending gap independently of a full inbox filesystem."""
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe pending audit-loss marker')
        return
    with os.fdopen(fd,'w') as marker:
        marker.write(str(time.time()));marker.flush();os.fsync(marker.fileno())


def persist_io_loss(spool):
    """Keep the volatile marker until a durable inbox marker commits."""
    if not os.path.lexists(spool.loss_marker):return True
    info=spool.loss_marker.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:raise ValueError('Unsafe pending audit-loss marker')
    try:
        with spool.db:spool.db.execute("INSERT OR REPLACE INTO meta VALUES ('io_error_at',?)",(time.time(),))
    except sqlite3.Error:
        spool.db.rollback();return False
    spool.loss_marker.unlink()
    return True


def mark_stream_gap(spool):
    try:spool.record_stream_gap()
    except sqlite3.Error:
        # Preserve a possible gap even if the inbox cannot write.
        mark_io_loss(spool.loss_marker)
        spool.db.rollback()
        persist_io_loss(spool)


def consume(engine, spool):
    saved = engine.store.state('audit_spool_cursor') or {}
    cursor = saved.get('id', 0) if saved.get('identity') == spool.identity else 0
    rows = spool.batch(cursor)
    if rows:
        batch_checkpoint=copy.deepcopy(getattr(engine,'persistence_pending',{}))
        try:
            with engine.store.atomic():
                for identifier, received, boot, line, snapshots in rows:
                    if boot == engine.boot_id:
                        # Only the current assembly group is mutated; a shallow map
                        # preserves expired groups and a deep copy preserves this one.
                        checkpoint = dict(getattr(engine,'persistence_pending',{}))
                        match = re.match(r'^(?:node=\S+ )?type=\w+\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):',line)
                        if match:
                            key=engine.boot_id+':'+match[1]+':'+match[2]
                            if key in checkpoint:checkpoint[key]=copy.deepcopy(checkpoint[key])
                        engine.db.execute('SAVEPOINT audit_record')
                        try:
                            engine.audit_snapshots = json.loads(snapshots)
                            engine.account(line)
                        except (ValueError, KeyError, TypeError) as exc:
                            engine.db.execute('ROLLBACK TO audit_record')
                            engine.persistence_pending=checkpoint
                            prior=engine.store.state('audit_parse_error') or {}
                            engine.store.state('audit_parse_error', {'time':time.time(),'error':type(exc).__name__,'count':prior.get('count',1 if prior else 0)+1,'last_record_id':identifier})
                            engine.db.execute('RELEASE audit_record')
                        else:
                            engine.db.execute('RELEASE audit_record')
                        finally:
                            engine.audit_snapshots = None
                    else:
                        old = engine.store.state('audit_previous_boot_skipped') or 0
                        engine.store.state('audit_previous_boot_skipped', old+1)
                cursor = rows[-1][0]
                engine.store.state('audit_assembly', getattr(engine, 'persistence_pending', {}))
                engine.store.state('audit_spool_cursor', {'identity': spool.identity, 'id': cursor})
        except BaseException:
            engine.persistence_pending=batch_checkpoint
            raise
    spool.acknowledge(cursor)  # Crash before this deletion is harmless: the durable cursor skips replays.
    return len(rows)


def forward(config, stream):
    from agent import process_snapshot
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    spool = Spool(config)
    identity=process_snapshot(os.getpid()) or {}
    identity['boot_id']=boot
    marker=spool.path.parent/'producer.json'
    temporary=marker.with_suffix('.tmp');temporary.write_text(json.dumps(identity));temporary.chmod(0o600);temporary.replace(marker)
    last_alert=0
    pending=b''
    try:
        while True:
            waiting_for_space=not persist_io_loss(spool)
            try:
                ready,_,_=select.select([stream.fileno()],[],[],1 if waiting_for_space else None)
                if not ready:continue
                chunk=os.read(stream.fileno(),65536)
            except OSError:
                mark_stream_gap(spool)
                print('AEGIS AUDIT GAP: stream read failed',flush=True)
                raise
            if not chunk:
                if pending:
                    mark_stream_gap(spool)
                    print('AEGIS AUDIT GAP: stream ended with an incomplete record',flush=True)
                break
            lines=(pending+chunk).split(b'\n');pending=lines.pop()
            if len(pending)>65536:
                lines.append(pending);pending=b''
            entries=[]
            for raw in lines:
                line=raw.decode(errors='replace')
                if not selected(line):continue
                # Capture identities at receipt, never look up reused live PIDs on replay.
                pids=re.findall(r'\b(?:pid|ppid)=(\d+)',line)
                snapshots={pid:process_snapshot(int(pid)) for pid in pids[:2]}
                entries.append((line,boot,snapshots))
            if not entries:continue
            try:
                accepted=all(spool.append_batch(entries))
            except sqlite3.Error:
                # The inbox filesystem may be too full even to record the loss.
                # Keep a separate runtime marker and retry durably when space returns.
                mark_io_loss(spool.loss_marker)
                spool.db.rollback();accepted=False
            if not accepted and time.monotonic()-last_alert>5:
                print('AEGIS AUDIT LOSS: inbox full or unavailable; check disk and auditd health',flush=True)
                last_alert=time.monotonic()
    finally:
        spool.db.close()
