import os
import json
import pathlib
import select
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import console
import response


class GracefulShutdown(unittest.TestCase):
    def test_sigterm_finishes_transaction_before_read_only_access(self):
        with tempfile.TemporaryDirectory() as directory:
            script='''import agent,sys,time
store=agent.Store(dict(agent.DEFAULTS,data_dir=sys.argv[1]));stop=agent.shutdown_flag()
with store.atomic():
 store.db.execute("INSERT INTO state VALUES ('first','1')")
 print('TRANSACTION_OPEN',flush=True)
 time.sleep(1)
 store.db.execute("INSERT INTO state VALUES ('second','2')")
assert stop.is_set()
store.db.close()
'''
            env=dict(os.environ,PYTHONPATH=str(pathlib.Path(__file__).resolve().parents[1]))
            process=subprocess.Popen([sys.executable,'-u','-c',script,directory],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            self.addCleanup(lambda:process.kill() if process.poll() is None else None)
            ready,_,_=select.select([process.stdout],[],[],10)
            self.assertTrue(ready,'Child did not begin transaction')
            self.assertEqual(process.stdout.readline().strip(),'TRANSACTION_OPEN')
            process.send_signal(signal.SIGTERM)
            out,err=process.communicate(timeout=10)
            self.assertEqual(process.returncode,0,err)
            dbpath=pathlib.Path(directory)/'incidents.db'
            with sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True) as db:
                self.assertEqual(db.execute('SELECT key,value FROM state ORDER BY key').fetchall(),[('first','1'),('second','2')])
                self.assertEqual(db.execute('PRAGMA quick_check').fetchone()[0],'ok')
            self.assertFalse(pathlib.Path(str(dbpath)+'-journal').exists())

    def test_response_stops_between_cases(self):
        db=sqlite3.connect(':memory:');self.addCleanup(db.close)
        db.execute('CREATE TABLE cases(id TEXT,status TEXT,created_at REAL)')
        db.executemany('INSERT INTO cases VALUES (?,\'recognized\',?)',[(str(n),n) for n in range(3)])
        stop=threading.Event();engine=SimpleNamespace(db=db)
        with patch.object(response,'advance',side_effect=lambda *args,**kwargs:stop.set()) as advance:
            response.resume(engine,time.time(),stop)
        self.assertEqual(advance.call_count,1)

    def test_response_finishes_current_step_without_starting_the_next(self):
        db=sqlite3.connect(':memory:');self.addCleanup(db.close)
        db.execute('CREATE TABLE cases(id TEXT PRIMARY KEY,version INTEGER,status TEXT,evidence_json TEXT,analysis_json TEXT,result_json TEXT)')
        response.initialize(db);now=time.time();stop=threading.Event()
        data={'events':[{'event_time':now}], 'allowed_actions':[{'action':'revoke_app_session','token':'one'},{'action':'revoke_app_session','token':'two'}]}
        db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?)',('test',1,'recognized',json.dumps(data),'{}','{}'))
        engine=SimpleNamespace(db=db,c={'response_mode':'enforce'},boot_id='boot')
        def execute(request):
            stop.set();return {'verified':True}
        engine.execute=execute
        response.prepare(engine,'test',data);db.commit()
        response.advance(engine,'test',stop=stop)
        states=[row[0] for row in db.execute('SELECT status FROM response_steps WHERE case_id=? ORDER BY position',('test',))]
        self.assertEqual(states,['executed','pending'])
        self.assertEqual(db.execute('SELECT count(*) FROM response_attempts').fetchone()[0],1)

    def test_terminal_does_not_report_stopped_worker_online(self):
        now=time.time();data={'heartbeat':{'time':now},'sensor_health':{},'response_worker':{'time':now,'status':'stopped'}}
        text='\n'.join(console.render(data,120,30,now=now))
        self.assertIn('Response: CHECK WORKER',text)
        data['response_worker']['status']='idle'
        self.assertIn('Response: ONLINE','\n'.join(console.render(data,120,30,now=now)))
