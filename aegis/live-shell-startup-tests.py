#!/usr/bin/env python3
"""Exercise an inert system-wide shell startup fixture on the lab VM."""
import json,os,pathlib,socket,sqlite3,time
import coverage_check

DB='/var/lib/defense-agent/incidents.db'
def wait(fn,seconds=60):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        value=fn()
        if value:return value
        time.sleep(.3)
    raise AssertionError('Timed out waiting for shell-startup evidence')
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated lab VM')
    root=pathlib.Path('/etc/profile.d');path=root/('aegis_observation_'+str(time.time_ns())[-9:]+'.sh')
    if path.exists() or path.is_symlink():raise RuntimeError('Fixture path already exists')
    facts=coverage_check.inventory()
    if not facts.get('shell_watches',{}).get(str(root)):raise RuntimeError('Test requires the selected shell watch')
    marker='AEGIS_TEST_STARTUP_CONTENT';start=time.time()-1;created=None
    try:
        with path.open('x') as stream:
            info=os.fstat(stream.fileno());created=(info.st_dev,info.st_ino)
            stream.write('# '+marker+'\n')
        def recorded():
            with sqlite3.connect('file:'+DB+'?mode=ro',uri=True) as db:
                rows=db.execute("SELECT event_id,details_json FROM correlation_events WHERE kind='persistence_change' AND subject=? AND event_time>=?",(str(path),start)).fetchall()
            return next(((eid,json.loads(raw)) for eid,raw in rows if json.loads(raw).get('mechanism')=='shell_startup'),None)
        event_id,details=wait(recorded)
        def evidence():
            with sqlite3.connect('file:'+DB+'?mode=ro',uri=True) as db:
                rows=db.execute("SELECT c.evidence_json FROM cases c JOIN case_events e ON e.case_id=c.id WHERE e.event_id=? AND c.kind='persistence_change'",(event_id,)).fetchall()
            for raw, in rows:
                item=json.loads(raw)
                if any(e['event_id']==event_id for e in item.get('events',[])):return item
        snapshot=wait(evidence)
        checks={
            'Real system-wide startup change recorded':details.get('path')==str(path),
            'Startup file contents are absent from evidence':marker not in json.dumps(snapshot),
            'No automatic action authorized':not snapshot['allowed_actions'],
            'Installed watch is visible to inventory':facts['shell_watches'][str(root)],
        }
        for label,value in checks.items():
            print(json.dumps({'test':label,'passed':bool(value)}),flush=True)
            if not value:raise AssertionError(label)
    finally:
        if created:
            try:info=path.lstat()
            except FileNotFoundError:pass
            else:
                if (info.st_dev,info.st_ino)!=created:raise RuntimeError('Fixture identity changed; manual cleanup required')
                path.unlink()
    print('AEGIS_SHELL_STARTUP_LIVE_PASSED')
if __name__=='__main__':main()
