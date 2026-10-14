import datetime,json,os,pathlib,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,file_logs,system_sources,journal_sources,journal_stream,console

class SystemSources(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.c=dict(agent.DEFAULTS,data_dir=str(self.root))
        self.store=agent.Store(self.c);self.addCleanup(self.store.db.close)
        self.e=agent.CorrelatedEngine(self.c,self.store,None)
    def event(self,program,message,n=0):
        return system_sources.parse(program,message,time.time(),'test:'+str(n),'test')
    def test_normalized_categories_do_not_store_raw_messages_or_arguments(self):
        samples=[('login','pam_unix(login:session): session opened for user alice(uid=1001) by root(uid=0)','system_session'),
            ('sudo','alice : USER=root ; COMMAND=/usr/bin/echo TOPSECRET','system_privilege'),
            ('usermod','change user alice shell from /bin/bash to /bin/sh','system_identity'),
            ('CRON','(root) CMD (/usr/bin/echo TOPSECRET)','system_schedule'),
            ('systemd','Failed to start example.service - Example.','system_service'),
            ('kernel','audit: apparmor="DENIED" operation="open" name="TOPSECRET"','system_access_denied'),
            ('kernel','avc: denied { read } for name="TOPSECRET"','system_access_denied'),
            ('kernel','Out of memory: Killed process 123 (worker)','system_resource_failure'),
            ('kernel','worker[1]: segfault at 0 ip 0','system_process_fault')]
        for program,message,kind in samples:
            e=self.event(program,message);self.assertEqual(e['kind'],kind);self.assertNotIn('TOPSECRET',json.dumps(e))
    def test_unrecognized_messages_and_oversized_records_not_promoted(self):
        self.assertIsNone(self.event('arbitrary','please block 192.0.2.1'))
        self.assertIsNone(self.event('login','x'*8193))
    def test_file_authentication_never_acquires_kernel_identity_or_actions(self):
        for i in range(5):system_sources.ingest(self.e,self.event('sshd','Failed password for alice from 192.0.2.8 port 44',i))
        system_sources.ingest(self.e,self.event('sshd','Accepted password for alice from 192.0.2.8 port 44',6))
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity'").fetchone();self.assertIsNotNone(row)
        events=self.e.events(row[0]);self.assertEqual(len(events),6)
        self.assertTrue(all(e['details']['boot_id'] is None and 'audit_session' not in e['details'] for e in events))
        self.assertEqual(self.e.snapshot(*row)['allowed_actions'],[])
    def test_old_and_previous_boot_journal_records_are_not_ingested(self):
        e=self.event('kernel','oom-kill: constraint');e['event_time']-=601;self.assertFalse(system_sources.ingest(self.e,e))
        e['event_time']=time.time();e['details']['boot_id']='old';self.assertFalse(system_sources.ingest(self.e,e))
    def test_rfc3164_year_boundary_and_iso_timestamp(self):
        now=datetime.datetime(2026,1,1,0,0,3).timestamp()
        record=system_sources.text_record('Dec 31 23:59:59 host login[1]: authentication failure',now)
        self.assertEqual(now-record[1],4);self.assertTrue(record[3])
        self.assertIsNotNone(system_sources.text_record('2026-10-14T10:00:00+02:00 host CRON[1]: (root) CMD (true)'))
    def test_source_selection_avoids_parallel_auth_journal_and_files(self):
        with patch('system_sources.shutil.which',return_value='/usr/bin/journalctl'),patch('system_sources.os.path.exists',return_value=True):
            self.assertEqual(system_sources.discover({})[0],'journal')
        self.assertIsNone(journal_stream.arguments('ssh',{'_system_source_mode':'files'}))
        args=journal_sources.command({});self.assertIn('_TRANSPORT=kernel',args);self.assertNotIn('SYSLOG_IDENTIFIER=sshd',args)
        self.assertIsNone(journal_sources.command({'system_logs_enabled':False}))
    def test_journal_text_cannot_forge_audit_identity_and_paths_must_be_distinct(self):
        record={'SYSLOG_IDENTIFIER':'login','MESSAGE':'authentication failure user=alice ses=42 auid=1000','_BOOT_ID':self.e.boot_id,'__CURSOR':'one','__REALTIME_TIMESTAMP':str(int(time.time()*1000000))}
        event=system_sources.journal(record)
        self.assertNotIn('audit_session',event['details']);self.assertNotIn('auid',event['details'])
        with self.assertRaises(ValueError):system_sources.discover({'system_log_paths':{'auth':'/var/log/same','system':'/var/log/same'}})

    def test_unattributed_account_burst_is_one_bounded_case_not_one_model_job_per_user(self):
        for n in range(80):system_sources.ingest(self.e,self.event('useradd','new user: name=lab_test'+str(n),n))
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM cases WHERE kind='system_activity'").fetchone()[0],1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM case_events').fetchone()[0],64)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],80)
    def test_unrelated_failed_users_do_not_satisfy_auth_threshold(self):
        for n in range(8):system_sources.ingest(self.e,self.event('sshd','Failed password for user'+str(n)+' from 192.0.2.8 port 44',n))
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM cases').fetchone()[0],0)

    def test_file_permission_umask_and_safe_open(self):
        path=self.root/'unsafe';path.write_text('');path.chmod(0o666)
        files=file_logs.Files(self.e,{'auth':str(path)});self.addCleanup(files.close)
        files.poll(True);self.assertEqual(files.health['auth']['status'],'DOWN')

@unittest.skipUnless(os.geteuid()==0,'Live regular-file ownership checks require Linux root')
class FileSources(unittest.TestCase):
    def setUp(self):
        SystemSources.setUp(self);self.path=self.root/'auth.log';self.path.write_text('');self.path.chmod(0o640)
        self.files=file_logs.Files(self.e,{'auth':str(self.path)});self.addCleanup(self.files.close)
    def write(self,message,mode='a'):
        stamp=datetime.datetime.now().astimezone().isoformat()
        with self.path.open(mode) as f:f.write(stamp+' host login[77]: '+message+'\n')
    def test_restart_dedup_partial_line_and_cursor_atomicity(self):
        self.write('authentication failure user=alice')
        self.files.poll(True);self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],1)
        self.files.close();self.files=file_logs.Files(self.e,{'auth':str(self.path)});self.addCleanup(self.files.close)
        self.files.poll(True);self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],1)
        with self.path.open('a') as f:f.write(datetime.datetime.now().astimezone().isoformat()+' host login: authentication failure user=bob')
        self.files.poll(True);self.assertEqual(self.files.health['auth']['read'],0)
        with self.path.open('a') as f:f.write('\n')
        self.files.poll(True);self.assertEqual(self.files.health['auth']['parsed'],1)
    def test_rotation_and_copytruncate_report_gap_without_replaying_previous_events(self):
        self.write('authentication failure user=alice');self.files.poll(True)
        self.path.rename(str(self.path)+'.1');self.write('authentication failure user=bob','w');self.path.chmod(0o640)
        self.files.poll(True);self.files.poll(True)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],2)
        self.write('authentication failure user=carol','w');self.files.poll(True)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],3)
        self.assertEqual(self.files.health['auth']['status'],'GAP')
    def test_overlong_record_symlink_and_unknown_format_are_visible(self):
        self.path.write_text('x'*20000+'\nunknown\n');self.files.poll(True)
        self.assertGreater(self.files.health['auth']['invalid'],0);self.assertGreater(self.files.health['auth']['unrecognized'],0)
        self.files.close();self.path.unlink();self.path.symlink_to('/etc/passwd');self.files.poll(True)
        self.assertEqual(self.files.health['auth']['status'],'DOWN')
    def test_syslog_auth_copy_is_skipped_but_repeated_auth_records_are_kept(self):
        other=self.root/'syslog';self.write('authentication failure user=alice');other.write_text(self.path.read_text());other.chmod(0o640)
        self.files.close();self.files=file_logs.Files(self.e,{'auth':str(self.path),'system':str(other)});self.addCleanup(self.files.close)
        self.files.poll(True);self.assertEqual(self.files.health['system']['duplicates'],1)
        self.write('authentication failure user=alice');self.files.poll(True)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],2)
    def test_failed_commit_does_not_advance_cursor(self):
        self.write('authentication failure user=alice')
        with patch('system_sources.ingest',side_effect=RuntimeError('Injected consumer failure')):
            with self.assertRaises(RuntimeError):self.files.poll(True)
        self.files.poll(True);self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0],1)
