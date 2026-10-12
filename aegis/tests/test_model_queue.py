import json,pathlib,sqlite3,sys,tempfile,unittest,urllib.error,os
from contextlib import closing
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import ai_worker as w
import monitoring

class Queue(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=pathlib.Path(tmp.name);self.db=self.root/'cases.db'
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('CREATE TABLE cases(id TEXT, version INTEGER, evidence_json TEXT, status TEXT, updated_at REAL)')
        self.now=7201.;self.cfg={'max_calls_per_hour':40,'min_call_interval_seconds':8,'response_reserve_calls':10}
        for target,value in [('OUT',self.root),('DB',str(self.db))]:
            p=patch.object(w,target,value);p.start();self.addCleanup(p.stop)
        p=patch.object(w.time,'time',side_effect=lambda:self.now);p.start();self.addCleanup(p.stop)
        self.model=patch.object(w,'analyze',return_value={'status':'complete'}).start();self.addCleanup(patch.stopall)

    def row(self,name='routine',urgent=False):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute('INSERT INTO cases VALUES(?,1,?,?,?)',(name,json.dumps({'allowed_actions':[{'action':'test'}] if urgent else [],'policy':{}}),'awaiting_analysis',self.now-3));conn.commit()

    def state(self,calls=0,**extra):
        w.write(self.root/'correlation-worker-state.json',dict(hour=2,calls=calls,attempts={},**extra))

    def saved(self):return json.loads((self.root/'correlation-worker-state.json').read_text())
    def health(self):return monitoring.model_health(self.root,self.now)

    def test_actionable_case_precedes_routine_case(self):
        self.row();self.row('urgent',True);w.cycle(self.cfg)
        self.assertEqual(self.model.call_args.args[0]['id'],'urgent')
        self.assertEqual(self.saved()['calls'],1)

    def test_reserve_holds_routine_but_accepts_response_chain(self):
        self.row();self.state(30);w.cycle(self.cfg)
        self.model.assert_not_called();self.assertEqual(self.health()['status'],'RESPONSE BUDGET RESERVED')
        self.row('urgent',True);w.cycle(self.cfg);self.assertEqual(self.saved()['calls'],31)

    def test_hard_cap_blocks_even_urgent_case(self):
        self.row('urgent',True);self.state(40);w.cycle(self.cfg)
        self.model.assert_not_called();self.assertEqual(self.health()['status'],'BUDGET EXHAUSTED')
        self.assertEqual(self.health()['pending'],1)

    def test_spacing_survives_hour_rollover(self):
        self.row();self.state(40,last_call_at=7199);self.now=7202
        saved=self.saved();saved['hour']=1;w.write(self.root/'correlation-worker-state.json',saved)
        w.cycle(self.cfg);self.model.assert_not_called();self.assertEqual(self.saved()['calls'],0)
        self.assertEqual(self.health()['status'],'WAITING FOR MODEL')
        self.now=7208;w.cycle(self.cfg);self.model.assert_called_once()

    def test_provider_throttle_blocks_all_cases_and_survives_restart(self):
        self.row();self.model.side_effect=urllib.error.HTTPError('https://example.invalid',429,'throttle',{'Retry-After':'120'},None)
        w.cycle(self.cfg);self.assertEqual(self.saved()['calls'],1)
        self.row('urgent',True);self.now+=20;w.cycle(self.cfg)
        self.assertEqual(self.model.call_count,1);self.assertEqual(self.health()['status'],'MODEL UNAVAILABLE')
        self.now+=101;self.model.side_effect=None;w.cycle(self.cfg)
        self.assertEqual(self.model.call_count,2)

    def test_three_failures_produce_terminal_result(self):
        self.row();self.model.side_effect=TimeoutError()
        for delta in (0,20,40):self.now+=delta;w.cycle(self.cfg)
        result=json.loads((self.root/'routine-v1.json').read_text())
        self.assertEqual(result['status'],'failed');self.assertEqual(self.saved()['calls'],3)
        self.now+=100;w.cycle(self.cfg);self.assertEqual(self.model.call_count,3)

    def test_stale_and_malformed_health_is_unavailable(self):
        self.row();self.state(40);w.cycle(self.cfg);self.now+=46
        self.assertEqual(self.health()['status'],'MODEL UNAVAILABLE')
        (self.root/'heartbeat.json').write_text('[]')
        self.assertEqual(self.health()['status'],'MODEL UNAVAILABLE')

    def test_attempt_state_is_pruned_after_case_expires(self):
        self.state(attempts_unused=True)
        saved=self.saved();saved['attempts']={'expired-v1':{'n':2,'next':9999}}
        w.write(self.root/'correlation-worker-state.json',saved);w.cycle(self.cfg)
        self.assertEqual(self.saved()['attempts'],{})

    def test_invalid_budget_rejected(self):
        for cfg in ({'max_calls_per_hour':0},{'max_calls_per_hour':4,'response_reserve_calls':4},{'min_call_interval_seconds':0}):
            with self.assertRaises(ValueError):w.limits(cfg)

    def test_cost_reserved_on_disk_before_request(self):
        self.row()
        def request(row,cfg):
            self.assertEqual(self.saved()['calls'],1)
            self.assertEqual(self.saved()['last_call_at'],self.now)
            return {'status':'complete'}
        self.model.side_effect=request;w.cycle(self.cfg)

    def test_health_rejects_fifo_and_symlink(self):
        path=self.root/'heartbeat.json';os.mkfifo(path)
        self.assertEqual(self.health()['status'],'MODEL UNAVAILABLE')
        path.unlink();path.symlink_to(self.db)
        self.assertEqual(self.health()['status'],'MODEL UNAVAILABLE')

    def test_retry_limit_survives_hour_rollover(self):
        self.row();self.state()
        state=self.saved();state.update(hour=1,last_call_at=7100)
        state['attempts']={'routine-v1':{'n':2,'next':7100}}
        w.write(self.root/'correlation-worker-state.json',state)
        self.model.side_effect=TimeoutError();w.cycle(self.cfg)
        self.assertEqual(json.loads((self.root/'routine-v1.json').read_text())['status'],'failed')
