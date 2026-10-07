import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent
import audit_spool
import maintenance
import monitoring
import response
import test_correlated as fixtures
import test_sessions as sessions


class Operations(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=pathlib.Path(self.tmp.name)
        self.c=dict(agent.DEFAULTS,data_dir=str(root),audit_spool_dir=str(root/'audit'),ai_results_dir=str(root/'ai'),application_log=str(root/'app.jsonl'))
        (root/'ai').mkdir()
        self.store=agent.Store(self.c);self.addCleanup(self.store.db.close)
        self.engine=agent.CorrelatedEngine(self.c,self.store,None)
        self.spool=audit_spool.Spool(self.c);self.addCleanup(self.spool.db.close)

    def line(self,serial=1):
        return f'type=SYSCALL msg=audit({time.time()}:{serial}): success=yes pid=999999 ppid=999998 uid=0 auid=1000 ses=4 exe="/usr/bin/true" key="lab_root_exec"'

    def case(self,name='a',status='observing',age=0):
        event=self.engine.normalize('fixture',name,{},name,time.time()-age)
        identifier=self.engine.create_or_append('fixture',name,event)
        self.store.db.execute('UPDATE cases SET status=?,updated_at=? WHERE id=?',(status,time.time()-age,identifier));self.store.db.commit()
        return identifier

    def test_durable_inbox_and_monotonic_ack(self):
        self.spool.append(self.line(),self.engine.boot_id)
        second=audit_spool.Spool(self.c)
        self.assertEqual(len(second.batch(0)),1);second.db.close()
        self.assertEqual(audit_spool.consume(self.engine,self.spool),1)
        self.assertEqual(self.spool.health()['rows'],0)
        first=self.store.state('audit_spool_cursor')['id']
        self.spool.append(self.line(2),self.engine.boot_id)
        self.assertGreater(self.spool.batch(0)[0][0],first)

    def test_full_inbox_preserves_accepted_rows_and_reports_loss(self):
        self.spool.row_limit=2
        for n in range(3):self.spool.append(self.line(n),self.engine.boot_id)
        health=self.spool.health()
        self.assertEqual((health['rows'],health['accepted'],health['dropped']),(2,2,1))
        self.assertTrue(health['pressure'])
        self.spool.limit=1
        self.assertFalse(self.spool.append(self.line(),self.engine.boot_id))
        self.assertEqual(self.spool.health()['rows'],2)

    def test_failed_core_transaction_never_acknowledges_or_leaves_partial_evidence(self):
        self.spool.append(self.line(),self.engine.boot_id)
        original=self.engine.account
        def fail(line):original(line);raise RuntimeError('core interrupted')
        with patch.object(self.engine,'account',side_effect=fail):
            with self.assertRaises(RuntimeError):audit_spool.consume(self.engine,self.spool)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0],0)
        self.assertIsNone(self.store.state('audit_spool_cursor'))
        self.assertEqual(self.spool.health()['rows'],1)
        audit_spool.consume(self.engine,self.spool)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0],1)

    def test_crash_after_core_commit_before_ack_is_not_reprocessed(self):
        self.spool.append(self.line(),self.engine.boot_id)
        with patch.object(self.spool,'acknowledge',side_effect=RuntimeError('lost ack')):
            with self.assertRaises(RuntimeError):audit_spool.consume(self.engine,self.spool)
        with patch.object(self.engine,'account',side_effect=AssertionError('replayed committed row')):
            self.assertEqual(audit_spool.consume(self.engine,self.spool),0)
        self.assertEqual(self.spool.health()['rows'],0)

    def test_replay_never_substitutes_live_reused_pid(self):
        self.spool.append(self.line(),self.engine.boot_id,{'999999':{'pid':999999,'start_ticks':12,'cgroup':'saved'}})
        with patch.object(agent,'process_snapshot',side_effect=AssertionError('live PID lookup')):
            audit_spool.consume(self.engine,self.spool)
        data=json.loads(self.store.db.execute('SELECT details_json FROM correlation_events').fetchone()[0])
        self.assertEqual(data['start_ticks'],12)
        self.assertIsNone(data['parent_start_ticks'])

    def test_previous_boot_is_acknowledged_without_current_attribution(self):
        self.spool.append(self.line(),'previous-boot')
        audit_spool.consume(self.engine,self.spool)
        self.assertEqual(self.store.state('audit_previous_boot_skipped'),1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0],0)

    def test_persistence_assembly_survives_consumer_restart_between_records(self):
        self.engine.c['persistence_enabled']=True
        stamp=time.time()
        self.spool.append(f'type=SYSCALL msg=audit({stamp}:42): success=yes pid=999999 uid=0 auid=1000 ses=4 exe="/usr/bin/true" key="aegis_persistence"',self.engine.boot_id)
        audit_spool.consume(self.engine,self.spool)
        self.engine=agent.CorrelatedEngine(self.c,self.store,None);self.engine.c['persistence_enabled']=True
        self.spool.append(f'type=PATH msg=audit({stamp}:42): name="/etc/cron.d/lab_aegis_fixture" nametype=CREATE',self.engine.boot_id)
        audit_spool.consume(self.engine,self.spool)
        # JSON restores paths as lists: restart after PATH, before the final EOE.
        self.engine=agent.CorrelatedEngine(self.c,self.store,None)
        self.spool.append(f'type=EOE msg=audit({stamp}:42):',self.engine.boot_id)
        audit_spool.consume(self.engine,self.spool)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM correlation_events WHERE kind='persistence_change'").fetchone()[0],1)
        self.assertEqual(self.store.state('audit_assembly'),{})

    def test_retention_removes_terminal_related_rows_but_protects_active_cases(self):
        old=self.case('old',age=8*86400)
        active=self.case('active','recognized',age=8*86400)
        for identifier in (old,active):
            self.store.db.execute('INSERT INTO response_runs VALUES (?,?,?,?)',(identifier,'boot','hash',0))
            self.store.db.execute('INSERT INTO case_timings(case_id) VALUES (?)',(identifier,))
        self.store.db.commit()
        health=maintenance.maintain(self.engine)
        self.assertEqual(health['deleted_cases'],1)
        self.assertEqual(self.store.db.execute('SELECT id FROM cases').fetchall(),[(active,)])
        for table in maintenance.TABLES:
            self.assertEqual(self.store.db.execute('SELECT count(*) FROM '+table+' WHERE case_id=?',(old,)).fetchone()[0],0)

    def test_storage_pressure_never_deletes_fresh_or_active_evidence(self):
        self.engine.c['database_retention_bytes']=1
        old=self.case('old',age=700);fresh=self.case('fresh',age=10);active=self.case('active','awaiting_analysis',age=700)
        health=maintenance.maintain(self.engine)
        self.assertTrue(health['pressure'])
        self.assertEqual({r[0] for r in self.store.db.execute('SELECT id FROM cases')},{fresh,active})

    def test_model_cleanup_protects_pending_result_and_ignores_foreign_files_and_links(self):
        identifier=self.case('pending','awaiting_analysis')
        directory=pathlib.Path(self.c['ai_results_dir']);files=[]
        for name in (identifier+'-v1.json',identifier+'-v0.json','health.json','f'*24+'-v1.tmp'):
            path=directory/name;path.write_text('{}');os.utime(path,(0,0));files.append(path)
        (directory/('e'*24+'-v1.json')).symlink_to(files[2])
        health=maintenance.maintain(self.engine)
        self.assertTrue(files[0].exists());self.assertFalse(files[1].exists());self.assertTrue(files[2].exists());self.assertFalse(files[3].exists())
        self.assertEqual(health['deleted_model_files'],2)

    def test_case_export_is_complete_private_and_does_not_overwrite(self):
        identifier=self.case()
        path=pathlib.Path(self.tmp.name)/'export.json'
        maintenance.export_case(self.store.path,identifier,path)
        data=json.loads(path.read_text());self.assertEqual(data['case']['id'],identifier);self.assertEqual(len(data['case_events']),1)
        self.assertEqual(path.stat().st_mode&0o777,0o600)
        with self.assertRaises(FileExistsError):maintenance.export_case(self.store.path,identifier,path)

    def test_sqlite_database_allocation_limit_is_enforced(self):
        directory=pathlib.Path(self.tmp.name)/'limited';directory.mkdir()
        store=agent.Store(dict(self.c,data_dir=str(directory),database_max_bytes=1024*1024))
        try:
            store.db.execute('CREATE TABLE payload(data BLOB)')
            import sqlite3
            with self.assertRaises(sqlite3.DatabaseError):
                for _ in range(32):
                    store.db.execute('INSERT INTO payload VALUES (?)',(b'x'*65536,));store.db.commit()
            store.db.rollback()
            self.assertLessEqual(store.path.stat().st_size,1024*1024)
        finally:store.db.close()

    def test_meter_rate_and_percentile_are_bounded(self):
        meter=monitoring.Meter()
        for n in range(1000):meter.add(1,.002)
        self.assertEqual(len(meter.loops),256)
        data=meter.snapshot();self.assertEqual(data['loop_p95_ms'],2);self.assertGreater(data['records_per_second'],0)
        self.assertEqual(meter.count,0)

    @unittest.skipUnless(os.geteuid()==0,'Application log owner check requires root; run on VM')
    def test_app_rotation_only_after_committed_consumption(self):
        path=pathlib.Path(self.c['application_log']);path.write_text('example\n');path.chmod(0o600)
        self.engine.c['application_log_max_bytes']=1
        self.store.state('app_offset',{'ino':path.stat().st_ino,'offset':0})
        self.assertFalse(maintenance.rotate_consumed_app_log(self.engine));self.assertEqual(path.read_text(),'example\n')
        self.store.state('app_offset',{'ino':path.stat().st_ino,'offset':path.stat().st_size})
        self.assertTrue(maintenance.rotate_consumed_app_log(self.engine));self.assertEqual(path.stat().st_size,0)
        self.assertEqual(self.store.state('app_offset')['offset'],0)


class AsyncEnrollment(unittest.TestCase):
    setUp=fixtures.Correlation.setUp
    tearDown=fixtures.Correlation.tearDown
    build=sessions.SSHSessions.build
    names=sessions.SSHSessions.names
    proposal=fixtures.Correlation.proposal
    apply=sessions.SSHSessions.apply
    status=fixtures.Correlation.status

    def test_core_enrolls_without_executing_worker_finishes_from_another_connection(self):
        row=self.build();self.e.execute=None
        self.apply(row,self.proposal(row))
        self.assertEqual(self.status(row),'recognized');self.assertFalse(self.actions)
        self.e.tick();self.assertFalse(self.actions)
        worker_store=agent.Store(self.c)
        try:
            worker=agent.CorrelatedEngine(self.c,worker_store,self.execute)
            response.resume(worker,time.time())
        finally:worker_store.db.close()
        self.assertEqual(self.status(row),'defended');self.assertEqual(len(self.actions),3)
        timing=self.store.db.execute('SELECT collection_ms,response_ms FROM case_timings WHERE case_id=?',(row[0],)).fetchone()
        self.assertTrue(all(value is not None and value>=0 for value in timing))
