"""Continuous journal input; checkpoint only records committed by the consumer."""
import json
import queue
import subprocess
import threading
import time

def persist_loss(store, source, reason, stamp):
    if source not in ('ssh','journal_context') or reason not in ('invalid_record','cursor_gap'):raise ValueError('Invalid journal loss marker')
    value=store.state('journal_loss_'+source) or {}
    if reason=='invalid_record':value['invalid_records']=value.get('invalid_records',0)+1
    else:value['cursor_gap_at']=stamp
    store.state('journal_loss_'+source,value)


def bootstrap_loss(store, source, previous):
    if store.state('journal_loss_'+source) is not None:return
    value={key:previous[key] for key in ('cursor_gap_at','invalid_records') if isinstance(previous.get(key),(int,float)) and previous[key]>0}
    if value:store.state('journal_loss_'+source,value)


def restore_health(store, source, previous):
    saved=store.state('journal_loss_'+source) or {}
    result={key:previous[key] for key in ('last_received_at','cursor_gap_at','invalid_records') if isinstance(previous.get(key),(int,float)) and previous[key]>=0}
    for key in ('cursor_gap_at','invalid_records'):
        value=saved.get(key)
        if isinstance(value,(int,float)) and value>result.get(key,0):result[key]=value
    return result


class Checkpoints:
    def __init__(self, store):
        self.lock = threading.Lock()
        self.values = {source: store.state('journal_cursor_' + source) or {}
                       for source in ('ssh', 'journal_context')}

    def cursor(self, source):
        with self.lock:
            return self.values[source].get('cursor')

    def commit(self, store, processed):
        # Records and cursors may replay after a crash, but cursors never run ahead.
        for source, record in processed.items():
            cursor = record.get('__CURSOR')
            if not isinstance(cursor, str) or not cursor:
                continue
            value = {'cursor': cursor, 'boot_id': record.get('_BOOT_ID'), 'time': time.time()}
            store.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',
                             ('journal_cursor_' + source, json.dumps(value)))
        store.db.commit()
        with self.lock:
            for source in processed:
                self.values[source] = store.state('journal_cursor_' + source) or {}


def arguments(source, config, cursor=None):
    if source == 'journal_context':
        from journal_sources import command
        args = command(config)
        if not args:
            return None
    else:
        if config.get('system_logs_enabled',True) and config.get('_system_source_mode')=='files':return None
        args = ['journalctl', '--follow', '--since=10 minutes ago', '--output=json',
                '_COMM=sshd', '_COMM=sshd-session']
    if cursor:
        args = [arg for arg in args if not arg.startswith('--since=')]
        args.insert(1, '--after-cursor=' + cursor)
    return args


def enqueue(events, source, record, health):
    # Backpressure pauses the reader instead of dropping a record and advancing past it.
    while True:
        try:
            events.put((source, record), timeout=.5)
            return
        except queue.Full:
            health['backpressure_count'] = health.get('backpressure_count', 0) + 1


def reader(events, source, config, checkpoints, health):
    fallback = False
    while True:
        cursor = None if fallback else checkpoints.cursor(source)
        args = arguments(source, config, cursor)
        if not args:
            health['connected'] = False
            time.sleep(1)
            continue
        received = False
        try:
            with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  text=True, errors='replace') as process:
                from agent import process_snapshot
                snapshot=process_snapshot(process.pid) or {}
                health.update(pid=process.pid,start_ticks=snapshot.get('start_ticks'),connected=True)
                for line in process.stdout:
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict):
                            raise ValueError('Journal record must be an object')
                    except (TypeError, ValueError):
                        health['invalid_records'] = health.get('invalid_records', 0) + 1
                        enqueue(events,'journal_loss',{'source':source,'reason':'invalid_record','time':time.time()},health)
                        continue
                    enqueue(events, source, record, health)
                    received = True
                    health['last_received_at'] = time.time()
                code = process.wait()
            if code and cursor and not received:
                # Vacuuming may remove the checkpoint. Explicitly report a possible gap.
                health['cursor_gap_at'] = time.time()
                enqueue(events,'journal_loss',{'source':source,'reason':'cursor_gap','time':health['cursor_gap_at']},health)
                fallback = True
            elif received:
                fallback = False
        except OSError as exc:
            health['reader_error'] = str(exc)[:200]
        finally:
            health['connected'] = False
        time.sleep(1)
