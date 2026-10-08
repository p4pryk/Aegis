"""Root-private, bounded audit inbox; acknowledgment follows the core transaction."""
import json
import os
import pathlib
import re
import sqlite3
import time
import uuid


def selected(line):
    return bool(re.search(r'^(?:node=\S+ )?type=(?:USER_CHAUTHTOK|1108|GRP_CHAUTHTOK|1133|CHUSER_ID|1125|ACCT_LOCK|1135|ACCT_UNLOCK|1136|USER_MGMT|1102|GRP_MGMT|1132|ADD_GROUP|1116|DEL_GROUP|1117|CHGRP_ID|1119|DEL_USER|1115|CWD|1307|ADD_USER|1114|SYSCALL|1300|PATH|1302|EOE|1320|USER_LOGIN|1112|USER_START|1105|USER_END|1106)\s', line)) and (
        not re.search(r'type=(?:SYSCALL|1300)\s', line) or
        bool(re.search(r'\bkey="?(?:lab_root_exec|aegis_app_exec|aegis_persistence|aegis_identity)"?(?:\s|$)', line)))


class Spool:
    def __init__(self, config):
        self.limit = int(config.get('audit_spool_bytes', 16*1024*1024))
        self.row_limit = int(config.get('audit_spool_records', 50000))
        self.path = pathlib.Path(config.get('audit_spool_dir', '/var/lib/defense-agent-audit')) / 'inbox.db'
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=5)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA max_page_count=16384')  # 64 MiB at the default 4 KiB page size.
        self.db.executescript('''CREATE TABLE IF NOT EXISTS inbox(
            id INTEGER PRIMARY KEY AUTOINCREMENT, received REAL, boot TEXT, line TEXT, snapshots TEXT, bytes INTEGER);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value);
            INSERT OR IGNORE INTO meta VALUES ('bytes',0),('rows',0),('accepted',0),('dropped',0);''')
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
        return {**meta, 'limit_bytes': self.limit, 'oldest_seconds': max(0, time.time()-oldest[0]) if oldest else 0,
                'file_bytes': self.path.stat().st_size, 'pressure': meta['bytes'] >= .8*self.limit or meta['rows'] >= .8*self.row_limit}


def consume(engine, spool):
    saved = engine.store.state('audit_spool_cursor') or {}
    cursor = saved.get('id', 0) if saved.get('identity') == spool.identity else 0
    rows = spool.batch(cursor)
    if rows:
        with engine.store.atomic():
            for identifier, received, boot, line, snapshots in rows:
                if boot == engine.boot_id:
                    engine.audit_snapshots = json.loads(snapshots)
                    try:
                        engine.account(line)
                    except (ValueError, KeyError, TypeError) as exc:
                        engine.store.state('audit_parse_error', {'time': time.time(), 'error': type(exc).__name__})
                    finally:
                        engine.audit_snapshots = None
                else:
                    old = engine.store.state('audit_previous_boot_skipped') or 0
                    engine.store.state('audit_previous_boot_skipped', old+1)
            cursor = rows[-1][0]
            engine.store.state('audit_assembly', getattr(engine, 'persistence_pending', {}))
            engine.store.state('audit_spool_cursor', {'identity': spool.identity, 'id': cursor})
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
            chunk=os.read(stream.fileno(),65536)
            if not chunk:break
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
                spool.db.rollback();accepted=False
                try:
                    with spool.db:spool.db.execute("INSERT OR REPLACE INTO meta VALUES ('io_error_at',?)",(time.time(),))
                except sqlite3.Error:spool.db.rollback()
            if not accepted and time.monotonic()-last_alert>5:
                print('AEGIS AUDIT LOSS: inbox full or unavailable; check disk and auditd health',flush=True)
                last_alert=time.monotonic()
    finally:
        spool.db.close()
