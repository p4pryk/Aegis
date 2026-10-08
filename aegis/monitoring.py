"""Small bounded operational counters; no raw event data."""
import collections
import time


class Meter:
    def __init__(self):
        self.since = time.monotonic()
        self.count = 0
        self.loops = collections.deque(maxlen=256)

    def add(self, count, seconds):
        self.count += count
        self.loops.append(seconds*1000)

    def snapshot(self):
        now = time.monotonic()
        ordered = sorted(self.loops)
        result = {'records_per_second': round(self.count/max(.001, now-self.since), 1),
                  'loop_p95_ms': round(ordered[min(len(ordered)-1, int(len(ordered)*.95))], 2) if ordered else 0}
        self.count = 0
        self.since = now
        return result


def case_timing(engine, identifier, result):
    now = time.time()
    created = engine.db.execute('SELECT created_at FROM cases WHERE id=?', (identifier,)).fetchone()[0]
    row = engine.db.execute("SELECT max(time) FROM case_status_history WHERE case_id=? AND status='awaiting_analysis'", (identifier,)).fetchone()
    ready = row[0] or now
    started = result.get('started_at', now)
    completed = result.get('completed_at', now)
    if not all(type(v) in (int, float) and 0 <= v <= now+5 for v in (started, completed)):
        return
    engine.db.execute('INSERT OR REPLACE INTO case_timings(case_id,collection_ms,model_queue_ms,model_ms,result_wait_ms) VALUES (?,?,?,?,?)',
                      (identifier, max(0, ready-created)*1000, max(0, started-ready)*1000,
                       max(0, completed-started)*1000, max(0, now-completed)*1000))


def process_state(pid,start_ticks=None):
    """Probe liveness independently of event traffic; reject a recycled PID."""
    import pathlib
    try:
        raw=(pathlib.Path('/proc')/str(int(pid))/'stat').read_text()
        fields=raw[raw.rfind(')')+2:].split()
        if start_ticks is not None and int(fields[19])!=start_ticks:return 'exited'
        return 'stopped' if fields[0] in ('T','t') else 'exited' if fields[0] in ('Z','X') else 'running'
    except (OSError,ValueError,TypeError,IndexError):return 'unavailable'


def service_active(unit):
    import subprocess
    try:
        result=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=2)
        return result.stdout.strip()=='active'
    except (OSError,subprocess.TimeoutExpired):return False


def source_states(engine,spool,journals,pending,now,kernel_status=None):
    import json
    from journal_stream import arguments
    sources=[]
    def add(name,enabled,alive,last,backlog,lag,loss,reason,unit='records',issue='Loss or possible gap recorded; review history'):
        status='DISABLED' if not enabled else 'DOWN' if not alive else 'GAP' if loss else 'LAGGING' if backlog and lag>=5 else 'QUIET' if not last or now-last>=30 else 'LIVE'
        sources.append(dict(name=name,status=status,last_record_at=last,pending=backlog,lag_seconds=round(lag,1),unit=unit,
                            reason='Disabled by configuration' if not enabled else reason if not alive else issue if loss else 'Collector is alive; backlog is delayed' if status=='LAGGING' else 'Collector is alive; no recent records' if status=='QUIET' else 'Collector is alive; intake is current',
                            loss=loss,checked_at=now))
    health=spool.health();producer={}
    try:producer=json.loads((spool.path.parent/'producer.json').read_text())
    except (OSError,ValueError):pass
    audit=engine.store.state('sensor_health') or {}
    kernel=audit.get('audit',{}) if kernel_status is None else kernel_status
    alive=producer.get('start_ticks') is not None and producer.get('boot_id')==engine.boot_id and process_state(producer.get('pid'),producer.get('start_ticks'))=='running' and service_active('auditd.service') and kernel.get('enabled') in ('1','2')
    add('Kernel audit',True,alive,health.get('last_received_at'),health['rows'],health['oldest_seconds'],bool(health.get('dropped') or health.get('io_error_at') or int(kernel.get('lost',0))), 'Audit producer stopped, unavailable, or kernel audit disabled',issue=f"Kernel lost: {kernel.get('lost',0)}; inbox rejected: {health.get('dropped',0)}; check audit history")
    journal_active=service_active('systemd-journald.service')
    for key,name in (('ssh','SSH journal'),('journal_context','Service journal')):
        h=journals[key];count,age=pending.get(key,(0,0))
        enabled=arguments(key,engine.c) is not None
        alive=h.get('start_ticks') is not None and h.get('connected') and process_state(h.get('pid'),h.get('start_ticks'))=='running' and journal_active
        add(name,enabled,alive,h.get('last_received_at'),count,age,bool(h.get('cursor_gap_at') or h.get('invalid_records')), 'Journal reader stopped or unavailable',issue=f"Cursor gap: {'recorded' if h.get('cursor_gap_at') else 'none'}; invalid records: {h.get('invalid_records',0)}")
    h=getattr(engine,'app_health',{})
    # The bundled application's broker is the producer of the trusted JSONL file.
    producer_ok=all(service_active(unit) for unit in ('aegis-target-broker.service','aegis-target.service')) if engine.c.get('application_enabled',False) else False
    add('Application',engine.c.get('application_enabled',False),h.get('connected') and producer_ok and now-h.get('checked_at',0)<15,h.get('last_received_at'),h.get('pending_bytes',0),h.get('pending_seconds',0),bool(h.get('invalid_records') or engine.store.state('app_source_gap')), 'Application log unreadable or producer stopped',unit='bytes',issue=(engine.store.state('app_source_gap') or {}).get('reason','Invalid application records observed'))
    return sources


def visible_sources(data,now):
    """A stale core cannot paint last-known collector states as current."""
    health=data.get('sensor_health',{});sources=health.get('sources',[])
    if not sources:return [dict(name=name,status='UNKNOWN',reason='Waiting for source health',pending=0,unit='records',lag_seconds=0,last_record_at=None) for name in ('Kernel audit','SSH journal','Service journal','Application')]
    stale=not 0<=now-health.get('time',0)<15
    return [dict(source,status='STALE',reason='Core health expired; collector state is unknown') if stale else dict(source) for source in sources]
