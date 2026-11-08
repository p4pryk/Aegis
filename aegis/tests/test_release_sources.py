import json
import pathlib
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
import agent, application_sources, history_context, journal_sources, system_sources

class ReleaseSources(unittest.TestCase):
    def test_new_evidence_preserves_existing_review_and_starts_next_part(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory,response_mode='review')
            store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
            first=engine.normalize('identity_change','account',{},'first',time.time())
            original=engine.create_or_append('host_change','session',first)
            store.db.execute("UPDATE cases SET status='review_required',analysis_json=? WHERE id=?",(json.dumps({'summary':'investigate'}),original));store.db.commit()
            second=engine.normalize('process_exec','process',{},'second',time.time())
            followup=engine.create_or_append('host_change','session',second)
            self.assertNotEqual(original,followup)
            state,analysis=store.db.execute('SELECT status,analysis_json FROM cases WHERE id=?',(original,)).fetchone()
            self.assertEqual(state,'review_required');self.assertEqual(json.loads(analysis)['summary'],'investigate')
            self.assertEqual(store.db.execute('SELECT parent_id,part FROM case_parts WHERE case_id=?',(followup,)).fetchone(),(original,2))
            self.assertIn('second',[e['event_id'] for e in engine.events(followup)])
            store.db.close()
    def test_all_service_warning_priorities_selected(self):
        command=journal_sources.command({})
        for priority in range(5):self.assertIn('PRIORITY='+str(priority),command)
        self.assertNotIn('PRIORITY=4',journal_sources.command({'service_warnings_enabled':False}))
        event=system_sources.parse('custom-app','sensitive=do-not-copy',time.time(),'x','custom-app','boot',{'PRIORITY':'3'})
        self.assertEqual(event['kind'],'system_warning');self.assertNotIn('do-not-copy',json.dumps(event))
        self.assertIsNone(system_sources.parse('custom-app','normal',time.time(),'x','app','boot',{'PRIORITY':'6'}))
    def test_access_discovery_respects_ownership_and_opt_out(self):
        with patch.object(pathlib.Path,'lstat',return_value=Mock(st_mode=0o100640,st_uid=0)):
            self.assertEqual(len(application_sources.sources({})),3)
            self.assertEqual(application_sources.sources({'auto_access_logs':False}),{})
        with patch.object(pathlib.Path,'lstat',return_value=Mock(st_mode=0o120777,st_uid=0)):
            self.assertEqual(application_sources.sources({}),{})
    def test_host_continuations_preserve_unique_events_and_bounded_history(self):
        with tempfile.TemporaryDirectory() as directory:
            store=agent.Store(dict(agent.DEFAULTS,data_dir=directory));engine=agent.CorrelatedEngine(dict(agent.DEFAULTS,data_dir=directory),store,None)
            for n in range(200):
                event=engine.normalize('identity_change','account',{},'e'+str(n),time.time())
                engine.create_or_append('host_change','session',event)
            self.assertEqual(store.db.execute('SELECT count(DISTINCT event_id) FROM case_events').fetchone()[0],200)
            self.assertLessEqual(store.db.execute('SELECT max(n) FROM (SELECT count(*) n FROM case_events GROUP BY case_id)').fetchone()[0],64)
            identifier=store.db.execute('SELECT case_id FROM case_parts ORDER BY part DESC LIMIT 1').fetchone()[0]
            history=history_context.summarize(store.db,identifier)
            self.assertGreater(history['unique_events'],64);self.assertEqual(history['trust'],'historical_context_not_causal_not_actionable')
            store.db.close()
    def test_session_exec_and_temporary_executable_create_review_case(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory);store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
            import audit_spool
            self.assertTrue(audit_spool.selected('type=SYSCALL msg=audit(1:1): key="aegis_session_exec"'))
            with patch.object(agent,'process_snapshot',return_value=None):
                engine.audit_line('type=SYSCALL msg=audit('+str(time.time())+':999): success=yes pid=123 ppid=12 uid=1001 euid=1001 auid=1001 ses=9 exe="/tmp/payload" key="aegis_session_exec"')
            row=store.db.execute('SELECT id,kind FROM cases').fetchone()
            self.assertEqual(row[1],'host_change');self.assertEqual(len(engine.events(row[0])),1)
            snapshot=engine.snapshot(row[0],row[1],'session',1)
            self.assertEqual(snapshot['allowed_actions'],[])
            store.db.close()

    def test_long_history_deduplication_does_not_materialize_all_event_ids(self):
        import tracemalloc
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory);store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
            first=engine.normalize('application_event','app',{},'first',time.time())
            identifier=engine.create_or_append('application_activity','app:session',first)
            store.db.execute('INSERT INTO case_parts VALUES (?,?,?,?)',('old',identifier,None,0))
            store.db.executemany('INSERT INTO case_events VALUES (?,?,?,?,?,?)',(('old','historical-'+str(n).zfill(50),time.time(),'application_event','app','{}') for n in range(16000)));store.db.commit()
            old=engine.normalize('application_event','app',{},'historical-'+str(0).zfill(50),time.time())
            new=engine.normalize('application_event','app',{},'new',time.time())
            tracemalloc.start()
            try:
                engine.create_or_append('application_activity','app:session',new,[old])
                peak=tracemalloc.get_traced_memory()[1]
            finally:tracemalloc.stop()
            self.assertLess(peak,500000)
            self.assertEqual({e['event_id'] for e in engine.events(identifier)},{'first','new'})
            store.db.close()
