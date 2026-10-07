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
