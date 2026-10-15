"""Cross-batch evidence, restart, and delayed-response safety regressions."""
import hashlib,json,pathlib,sys,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,ai_worker,presentation
import test_application_sources as applications
import test_correlated as correlation

class Parts(unittest.TestCase):
    setUp=applications.Applications.setUp
    event=applications.Applications.event
    insert=applications.Applications.insert
    cases=applications.Applications.cases

    def test_late_consequence_survives_rollover_restart_and_duplicate(self):
        events=[]
        for n in range(95):
            if n==40:self.engine=agent.CorrelatedEngine(self.config,self.store,None)
            event=self.event('permission_changed' if n==94 else 'security_alert',session_id='one',user='alice')
            events.append(event);self.insert(event)
        rows=self.cases();self.assertEqual(len(rows),4)
        snapshots=[self.engine.snapshot(*row) for row in rows]
        self.assertEqual({e['event_id'] for s in snapshots for e in s['events']},{e['event_id'] for e in events})
        self.assertTrue(all(len(s['events'])<=32 and len(agent.canonical(s).encode())<48000 for s in snapshots))
        self.assertIn(events[-1]['event_id'],{e['event_id'] for e in snapshots[-1]['events']})
        self.assertEqual([s['continuation']['part'] for s in snapshots],[1,2,3,4])
        self.assertEqual(snapshots[-1]['continuation']['parent_id'],rows[-2][0])
        sealed=self.store.db.execute('SELECT evidence_json,version FROM cases WHERE id=?',(rows[0][0],)).fetchone()
        self.insert(events[0]);self.assertEqual(self.cases(),rows)
        self.assertEqual(sealed,self.store.db.execute('SELECT evidence_json,version FROM cases WHERE id=?',(rows[0][0],)).fetchone())
        self.assertFalse(any(s['allowed_actions'] for s in snapshots))

    def test_same_user_and_ip_different_sessions_stay_separate(self):
        for session in ('one','two'):
            for _ in range(3):self.insert(self.event('security_alert',session_id=session,user='alice',ip='192.0.2.1'))
        self.assertEqual(len(self.cases()),2)
        for row in self.cases():
            snap=self.engine.snapshot(*row)
            self.assertEqual(len(snap['events']),3)
            self.assertEqual(len({e['details']['session_id_hash'] for e in snap['events']}),1)

    def test_continuation_keeps_authentication_and_consequence_context(self):
        for _ in range(5):self.insert(self.event(outcome='failure',user='alice',ip='192.0.2.1'))
        self.insert(self.event(outcome='success',session_id='one',user='alice',ip='192.0.2.1'))
        self.insert(self.event('account_created',session_id='one',user='alice'))
        for _ in range(60):self.insert(self.event('security_alert',session_id='one',user='alice'))
        snap=self.engine.snapshot(*self.cases()[-1])
        self.assertGreater(snap['continuation']['part'],1)
        self.assertEqual({e['details']['outcome'] for e in snap['events'] if e['details']['event']=='authentication'},{'failure','success'})
        self.assertTrue(any(e['details']['event']=='account_created' for e in snap['events']))
        self.assertFalse(snap['allowed_actions'])

    def test_active_case_pressure_is_reported_and_bounded(self):
        for n in range(260):self.insert(self.event('security_alert',session_id=str(n)))
        self.assertEqual(len(self.cases()),256)
        self.assertEqual(self.store.state('correlation_overload')['active_cases'],256)

class Deferred(unittest.TestCase):
    setUp=correlation.Correlation.setUp
    tearDown=correlation.Correlation.tearDown
    account=correlation.Correlation.account
    chain=correlation.Correlation.chain
    awaiting=correlation.Correlation.awaiting
    proposal=correlation.Correlation.proposal
    apply=correlation.Correlation.apply
    status=correlation.Correlation.status

    def age(self,row,seconds):
        self.store.db.execute('UPDATE analysis_queue SET queued_at=? WHERE case_id=?',(time.time()-seconds,row[0]));self.store.db.commit()

    def test_late_positive_verdict_is_recorded_but_cannot_execute(self):
        self.chain();row=self.awaiting();self.age(row,100)
        self.apply(row,self.proposal(row))
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
        analysis=json.loads(self.store.db.execute('SELECT analysis_json FROM cases WHERE id=?',(row[0],)).fetchone()[0])
        self.assertTrue(analysis['summary']);self.assertEqual(analysis['proposed_actions'],[])
        self.assertFalse(self.store.db.execute('SELECT * FROM response_runs').fetchall())

    def test_reboot_preserves_wait_but_disables_automatic_response(self):
        self.chain();row=self.awaiting()
        self.e=agent.CorrelatedEngine(self.c,self.store,self.execute);self.e.boot_id='new-boot'
        self.apply(row,self.proposal(row));self.assertFalse(self.actions);self.assertEqual(self.status(row),'analysis_error')

    def test_budget_recovers_after_restart_and_review_only_analysis_completes(self):
        self.account();row=self.awaiting();self.age(row,100)
        now=time.time();root=pathlib.Path(self.c['ai_results_dir'])
        ai_worker.write(root/'correlation-worker-state.json',dict(hour=int(now//3600),calls=40,attempts={}))
        cfg=dict(max_calls_per_hour=40,response_reserve_calls=10,min_call_interval_seconds=8)
        with patch.object(ai_worker,'DB',str(self.store.path)),patch.object(ai_worker,'OUT',root),patch.object(ai_worker,'analyze',return_value=self.proposal(row)) as model:
            ai_worker.cycle(cfg);model.assert_not_called();self.e.tick()
            self.assertEqual(self.status(row),'awaiting_analysis')
            self.assertEqual(self.store.db.execute('SELECT reason FROM analysis_queue WHERE case_id=?',(row[0],)).fetchone()[0],'BUDGET EXHAUSTED')
            self.e=agent.CorrelatedEngine(self.c,self.store,self.execute)
            # A persisted previous-hour budget naturally resets on the next cycle.
            saved=json.loads((root/'correlation-worker-state.json').read_text());saved['hour']-=1
            ai_worker.write(root/'correlation-worker-state.json',saved)
            ai_worker.cycle(cfg);model.assert_called_once();self.e.tick()
        self.assertEqual(self.status(row),'insufficient_evidence');self.assertFalse(self.actions)

    def test_restart_does_not_extend_queue_deadline(self):
        self.account();row=self.awaiting();self.age(row,7201)
        self.e=agent.CorrelatedEngine(self.c,self.store,self.execute);self.e.tick()
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
        self.assertNotIn('pending',presentation.case_display({'status':'analysis_error'})['summary'].lower())

if __name__=='__main__':unittest.main()
