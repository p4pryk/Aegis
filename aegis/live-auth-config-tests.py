#!/usr/bin/env python3
"""Verify audit collection using inert, uniquely named files on the AEGIS lab VM."""
import json,os,pathlib,socket,sqlite3,time

DB='/var/lib/defense-agent/incidents.db'
checks=[]
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
def query(sql,args=()):
    with sqlite3.connect(DB,timeout=5) as db:return db.execute(sql,args).fetchall()
def wait(fn,seconds=60):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        result=fn()
        if result:return result
        time.sleep(.3)
    raise AssertionError('Timed out waiting for audit event')

def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    suffix=str(time.time_ns())
    paths=[pathlib.Path('/etc/ssh/sshd_config.d/aegis-lab-'+suffix+'.conf'),pathlib.Path('/etc/pam.d/aegis-lab-'+suffix)]
    made=[];started=time.time()-1;sentinel='AEGIS_AUTH_TEST_'+suffix
    try:
        for path in paths:
            with path.open('x') as handle:handle.write('# '+sentinel+'\n')
            made.append(path)
        def events():
            rows=query("SELECT subject,details_json FROM correlation_events WHERE kind='security_file_change' AND event_time>=?",(started,))
            selected=[(subject,json.loads(details)) for subject,details in rows if subject in map(str,paths)]
            return selected if {subject for subject,_ in selected}==set(map(str,paths)) else None
        rows=wait(events)
        check('Both real audit paths reached the installed collector',len(rows)>=2)
        check('Authentication configuration changes carry audit metadata',all(details.get('mechanism')=='authentication_configuration' and details.get('source')=='auditd' and details.get('boot_id') for _,details in rows))
        check('File contents are not retained in normalized events',sentinel not in json.dumps(rows))
        def case():
            cases=query("SELECT evidence_json FROM cases WHERE kind='host_change' AND updated_at>=?",(started,))
            for (raw,) in cases:
                evidence=json.loads(raw)
                subjects={event.get('subject') for event in evidence.get('events',[])}
                if set(map(str,paths))<=subjects:return evidence
        evidence=wait(case)
        check('Changes are visible together without authorizing a response',not evidence['allowed_actions'])
        check('File contents are absent from incident evidence',sentinel not in json.dumps(evidence))
    finally:
        for path in made:path.unlink(missing_ok=True)
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))

if __name__=='__main__':main()
