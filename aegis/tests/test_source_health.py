import json,pathlib,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,audit_spool,monitoring,console,app_correlation

class SourceHealth(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.c=dict(agent.DEFAULTS,data_dir=self.temp.name,audit_spool_dir=self.temp.name+'/audit',application_enabled=True,application_log=self.temp.name+'/application.jsonl')
        self.store=agent.Store(self.c);self.addCleanup(self.store.db.close)
        self.e=agent.CorrelatedEngine(self.c,self.store,None);self.spool=audit_spool.Spool(self.c);self.addCleanup(self.spool.db.close)
        (self.spool.path.parent/'producer.json').write_text(json.dumps({'boot_id':self.e.boot_id,'pid':123,'start_ticks':12}))
        self.store.state('sensor_health',{'audit':{'enabled':'1','lost':'0'}})
        self.now=time.time();self.e.app_health={'connected':True,'checked_at':self.now}
        self.journals={k:{'connected':True,'pid':124,'start_ticks':12} for k in ('ssh','journal_context')}

    def states(self,pending=None,process='running',active=True):
        with patch.object(monitoring,'process_state',return_value=process),patch.object(monitoring,'service_active',return_value=active):
            return monitoring.source_states(self.e,self.spool,self.journals,pending or {},self.now)

    def test_no_events_with_live_collectors_is_quiet_not_down(self):
        self.assertTrue(all(s['status']=='QUIET' for s in self.states()))

    def test_stopped_process_is_down_even_with_recent_events(self):
        for h in self.journals.values():h['last_received_at']=self.now
        self.assertEqual(self.states(process='stopped')[1]['status'],'DOWN')
        self.assertEqual(self.states(process='unavailable')[0]['status'],'DOWN')

    def test_service_unavailable_overrides_readable_log(self):
        self.assertTrue(all(s['status']=='DOWN' for s in self.states(active=False)))

    def test_current_intake_is_live_and_backlog_has_own_source(self):
        self.journals['ssh']['last_received_at']=self.now
        self.assertEqual(self.states()[1]['status'],'LIVE')
        rows=self.states({'ssh':(50,20)})
        self.assertEqual(rows[1]['status'],'LAGGING');self.assertEqual(rows[2]['status'],'QUIET')

    def test_historical_gap_survives_a_live_reader(self):
        self.journals['ssh'].update(cursor_gap_at=self.now-100,last_received_at=self.now)
        self.assertEqual(self.states()[1]['status'],'GAP')
        self.store.state('app_source_gap',{'time':self.now-100})
        self.assertEqual(self.states()[3]['status'],'GAP')

    def test_disabled_sources_are_explicit(self):
        self.c.update(application_enabled=False,journal_units=[],journal_identifiers=[],journal_comms=[])
        rows=self.states();self.assertEqual(rows[2]['status'],'DISABLED');self.assertEqual(rows[3]['status'],'DISABLED')

    def test_stale_core_never_shows_current_healthy_sources(self):
        data={'sensor_health':{'time':self.now-16,'sources':self.states()}}
        self.assertTrue(all(s['status']=='STALE' for s in monitoring.visible_sources(data,self.now)))
        self.assertTrue(all(s['status']=='UNKNOWN' for s in monitoring.visible_sources({},self.now)))

    def test_audit_last_intake_persists_after_ack(self):
        self.spool.append('test',self.e.boot_id)
        self.spool.acknowledge(self.spool.batch(0)[0][0])
        self.assertEqual(self.spool.health()['rows'],0)
        self.assertGreater(self.spool.health()['last_received_at'],0)

    def test_missing_application_log_is_down(self):
        app_correlation.ingest(self.e)
        self.assertEqual(self.states()[3]['status'],'DOWN')

    def test_console_source_panel_is_bounded_and_marks_stale(self):
        data={'sensor_health':{'time':self.now-20,'sources':self.states()}}
        text='\n'.join(console.source_lines(data,100,self.now));self.assertIn('STALE',text)
        for width,height in ((120,42),(65,25),(30,10)):
            lines=console.render(data,width,height,mode='sources',now=self.now)
            self.assertEqual(len(lines),height);self.assertTrue(all(console.cells(s)<=width for s in lines))

    def test_process_probe_checks_birth_identity_and_stop_state(self):
        fields=['S','1']+['0']*17+['55']
        with patch.object(pathlib.Path,'read_text',return_value='12 (collector name) '+' '.join(fields)):
            self.assertEqual(monitoring.process_state(12,55),'running')
            self.assertEqual(monitoring.process_state(12,56),'exited')
        fields[0]='T'
        with patch.object(pathlib.Path,'read_text',return_value='12 (collector name) '+' '.join(fields)):
            self.assertEqual(monitoring.process_state(12,55),'stopped')

    def test_app_truncation_is_reported_as_possible_gap(self):
        import stat
        from types import SimpleNamespace
        path=pathlib.Path(self.c['application_log']);path.write_text('')
        self.store.state('app_offset',{'ino':path.stat().st_ino,'offset':100})
        with patch.object(app_correlation.os,'fstat',return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_ino=path.stat().st_ino,st_size=0)):
            app_correlation.ingest(self.e)
        self.assertIn('truncated',self.store.state('app_source_gap')['reason'])
        self.assertEqual(self.states()[3]['status'],'GAP')

    def test_invalid_app_record_is_not_silently_healthy(self):
        import stat
        from types import SimpleNamespace
        path=pathlib.Path(self.c['application_log']);path.write_text('invalid fixture\n')
        with patch.object(app_correlation.os,'fstat',return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_ino=path.stat().st_ino,st_size=path.stat().st_size)):
            app_correlation.ingest(self.e)
        self.assertEqual(self.states()[3]['status'],'GAP')

    def test_stopped_http_service_is_down_even_when_broker_is_alive(self):
        with patch.object(monitoring,'process_state',return_value='running'),patch.object(monitoring,'service_active',side_effect=lambda unit:unit!='aegis-target.service'):
            rows=monitoring.source_states(self.e,self.spool,self.journals,{},self.now)
        self.assertEqual(rows[3]['status'],'DOWN')

    def test_current_kernel_probe_overrides_old_saved_status(self):
        self.store.state('sensor_health',{'audit':{'enabled':'0','lost':'0'}})
        with patch.object(monitoring,'process_state',return_value='running'),patch.object(monitoring,'service_active',return_value=True):
            rows=monitoring.source_states(self.e,self.spool,self.journals,{},self.now,{'enabled':'1','lost':'0'})
        self.assertEqual(rows[0]['status'],'QUIET')
