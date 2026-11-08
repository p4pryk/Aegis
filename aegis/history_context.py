"""Bounded summaries of earlier parts; never response evidence or causal links."""
import collections

def summarize(db, identifier):
    row=db.execute('SELECT root_id,part FROM case_parts WHERE case_id=?',(identifier,)).fetchone()
    if not row or row[1]<=1:return None
    parts=db.execute('SELECT case_id FROM case_parts WHERE root_id=? AND part<? ORDER BY part DESC LIMIT 8',(row[0],row[1])).fetchall()
    counts=collections.Counter();start=end=None;seen=set()
    for case_id, in parts:
        for eid,stamp,kind in db.execute('SELECT event_id,event_time,kind FROM case_events WHERE case_id=? LIMIT 256',(case_id,)):
            if eid in seen:continue
            seen.add(eid);counts[kind]+=1
            start=stamp if start is None else min(start,stamp);end=stamp if end is None else max(end,stamp)
    return {'trust':'historical_context_not_causal_not_actionable','parts':[r[0] for r in parts],
            'earlier_parts_omitted':row[1]-1>len(parts),'event_counts':dict(counts.most_common(32)),
            'first_event':start,'last_event':end,'unique_events':len(seen)}
