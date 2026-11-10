#!/usr/bin/env python3
"""Isolated VM test of orderly shutdown and journal replay under log activity."""
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import tempfile
import time

DB=pathlib.Path('/var/lib/defense-agent/incidents.db')
UNITS=('defense-response','defense-agent','defense-executor')

def run(*args,check=True,timeout=90):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=timeout)

def wait_for(fn,seconds=90):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try:
            value=fn()
            if value:return value
        except sqlite3.Error:pass
        time.sleep(.25)
    raise RuntimeError('Timed out waiting for collector replay')

def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only on the isolated AEGIS test VM')
    config=json.loads(pathlib.Path('/etc/defense-agent/config.json').read_text())
    if not config.get('lab_response_enabled'):raise SystemExit('Explicit demo profile required')
    ai_active=run('systemctl','is-active','--quiet','defense-agent-ai',check=False).returncode==0
    run('systemctl','stop','defense-agent-ai')
    suffix=str(time.time_ns())[-8:];generator=None
    try:
        for cycle in range(3):
            prefix='aegis_stop_'+suffix+'_'+str(cycle)+'_';start=time.time()
            with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8') as fixture:
                fixture.writelines('new user: name='+prefix+str(n)+'\n' for n in range(120));fixture.flush()
                generator=subprocess.Popen(['logger','-p','user.notice','-t','useradd','-f',fixture.name],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
                run('systemctl','stop',*UNITS)
                _,error=generator.communicate(timeout=30)
                if generator.returncode:raise RuntimeError('Fixture logger failed: '+error[:100])
                generator=None
            with sqlite3.connect(DB.as_uri()+'?mode=ro',uri=True,timeout=10) as db:
                assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
                db.execute('SELECT count(*) FROM cases').fetchone()
            print(json.dumps({'test':'readonly_database_after_shutdown','cycle':cycle,'passed':True}),flush=True)
            # This marker is emitted only while the core is stopped, so its
            # later arrival demonstrates replay rather than pre-stop intake.
            downtime=prefix+'downtime'
            run('logger','-p','user.notice','-t','useradd','new user: name='+downtime)
            with sqlite3.connect(DB.as_uri()+'?mode=ro',uri=True,timeout=10) as db:
                assert db.execute("SELECT count(*) FROM correlation_events WHERE kind='system_identity' AND subject=?",(downtime,)).fetchone()[0]==0
            run('systemctl','start','defense-executor','defense-agent','defense-response')
            def observed():
                with sqlite3.connect(DB.as_uri()+'?mode=ro',uri=True,timeout=10) as db:
                    return db.execute("SELECT count(DISTINCT subject) FROM correlation_events WHERE kind='system_identity' AND subject LIKE ? AND event_time>=?",(prefix+'%',start-2)).fetchone()[0]
            def complete():
                count=observed();return count if count>=121 else None
            count=wait_for(complete)
            print(json.dumps({'test':'journal_replayed_after_shutdown','cycle':cycle,'passed':count==121,'records':count}),flush=True)
            if count!=121:raise AssertionError('Unexpected fixture event count')
            time.sleep(11)
    finally:
        if generator and generator.poll() is None:generator.terminate();generator.wait(timeout=10)
        subprocess.run(['systemctl','start','defense-executor','defense-agent','defense-response'],capture_output=True)
        if ai_active:subprocess.run(['systemctl','start','defense-agent-ai'],capture_output=True)
    print('LIVE_SHUTDOWN_VERIFIED')

if __name__=='__main__':main()
