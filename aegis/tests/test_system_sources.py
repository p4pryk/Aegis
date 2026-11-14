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
    def test_polkit_denial_is_reviewable_without_raw_or_automatic_response(self):
        event=self.event('polkitd','Operator FAILED to authenticate for action SECRET_VALUE')
        self.assertEqual(event['kind'],'system_authorization_denied');self.assertTrue(event['details']['review_signal'])
        self.assertNotIn('SECRET_VALUE',json.dumps(event));system_sources.ingest(self.e,event)
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity'").fetchone()
        self.assertIsNotNone(row);self.assertEqual(self.e.snapshot(*row)['allowed_actions'],[])
        self.assertIsNone(self.event('polkitd','Registered authentication agent'))
    def test_security_service_stopping_is_not_itself_a_compromise(self):
        stopped=self.event('systemd','Stopped auditd.service for SECRET_DETAIL')
        self.assertTrue(stopped['details']['review_signal']);self.assertTrue(stopped['details']['security_service'])
        self.assertNotIn('SECRET_DETAIL',json.dumps(stopped));system_sources.ingest(self.e,stopped)
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity'").fetchone()
        self.assertEqual(self.e.snapshot(*row)['allowed_actions'],[])
        self.assertFalse(self.event('systemd','Started auditd.service')['details']['review_signal'])
        self.assertFalse(self.event('systemd','Stopped example.service')['details']['review_signal'])
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
    def test_file_ssh_cases_separate_accounts_and_ips_and_show_reported_success(self):
        for i in range(5):
            system_sources.ingest(self.e,self.event('sshd','Failed password for alice from 192.0.2.8 port 44',i))
            system_sources.ingest(self.e,self.event('sshd','Failed password for bob from 192.0.2.9 port 44',i+10))
        system_sources.ingest(self.e,self.event('sshd','Accepted password for alice from 192.0.2.8 port 44',20))
        rows=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity' ORDER BY subject").fetchall()
        self.assertEqual(len(rows),2)
        alice=next(row for row in rows if row[2].endswith('/alice'))
        evidence=self.e.snapshot(*alice)
        self.assertEqual({e['details'].get('user') for e in evidence['events']},{'alice'})
        self.assertTrue(any(s['kind']=='reported_ssh_success_after_failures' for s in evidence['signals']))
        self.assertEqual(evidence['allowed_actions'],[])
        case={'id':alice[0],'kind':alice[1],'subject':alice[2],'version':alice[3],'status':'insufficient_evidence','evidence_json':json.dumps(evidence)}
        self.assertIn('File reports SSH login','\n'.join(console.case_lines({'cases':[case]},120)))
    def test_file_ssh_out_of_order_success_correlates_after_restart(self):
        now=time.time()
        success=self.event('sshd','Accepted publickey for alice from 192.0.2.8 port 44',99)
        success['event_time']=now;system_sources.ingest(self.e,success)
        self.e=agent.CorrelatedEngine(self.c,self.store,None)
        for i in range(5):
            e=self.event('sshd','Failed publickey for alice from 192.0.2.8 port 44',i)
            e['event_time']=now-10-i;system_sources.ingest(self.e,e)
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity'").fetchone()
        self.assertIsNotNone(row);evidence=self.e.snapshot(*row)
        self.assertTrue(any(s['kind']=='reported_ssh_success_after_failures' for s in evidence['signals']))
        self.assertEqual(evidence['allowed_actions'],[])
    def test_file_ssh_does_not_claim_success_after_later_failures_or_other_ip(self):
        now=time.time();success=self.event('sshd','Accepted publickey for alice from 192.0.2.8 port 44',99)
        success['event_time']=now-10;system_sources.ingest(self.e,success)
        for i in range(5):
            e=self.event('sshd','Failed publickey for alice from 192.0.2.8 port 44',i);e['event_time']=now;system_sources.ingest(self.e,e)
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity'").fetchone()
        self.assertFalse(self.e.snapshot(*row)['signals'])
    def test_file_ssh_continuation_preserves_bounded_authentication_chain(self):
        now=time.time()
        for n in range(5):
            e=self.event('sshd','Failed password for alice from 192.0.2.8 port 44',n);e['event_time']=now-20;system_sources.ingest(self.e,e)
        for n in range(70):
            e=self.event('sshd','Accepted password for alice from 192.0.2.8 port 44',n+100);e['event_time']=now-10;system_sources.ingest(self.e,e)
        rows=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='system_activity' ORDER BY created_at DESC").fetchall()
        self.assertGreater(len(rows),1)
        evidence=self.e.snapshot(*rows[0]);self.assertLessEqual(len(evidence['events']),64)
        self.assertTrue(any(s['kind']=='reported_ssh_success_after_failures' for s in evidence['signals']))
        self.assertEqual(evidence['allowed_actions'],[])
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
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM cases WHERE kind='system_activity'").fetchone()[0],2)
        self.assertEqual(self.store.db.execute('SELECT count(DISTINCT event_id) FROM case_events').fetchone()[0],80)
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
    def test_invalid_utf8_is_a_durable_gap(self):
        self.path.write_bytes(b'\xff\n');self.files.poll(True)
        self.assertEqual((self.files.health['auth']['invalid'],self.files.health['auth']['status']),(1,'GAP'))
        self.files.close();self.files=file_logs.Files(self.e,{'auth':str(self.path)});self.addCleanup(self.files.close)
        self.files.poll(True)
        self.assertEqual((self.files.health['auth']['invalid'],self.files.health['auth']['status']),(1,'GAP'))
    def test_unsafe_open_log_recovers_after_safe_replacement(self):
        self.write('authentication failure user=alice');self.files.poll(True)
        self.path.chmod(0o666);self.write('authentication failure user=unsafe');self.files.poll(True)
        self.assertEqual(self.files.health['auth']['status'],'DOWN');self.assertNotIn(str(self.path),self.files.handles)
        self.path.rename(self.root/'old-unsafe');self.write('authentication failure user=bob','w');self.path.chmod(0o640)
        self.files.poll(True)
        subjects={row[0] for row in self.store.db.execute('SELECT subject FROM observations')}
        self.assertEqual(subjects,{'alice','bob'});self.assertEqual(self.files.health['auth']['status'],'GAP')
        self.files.close();self.files=file_logs.Files(self.e,{'auth':str(self.path)});self.addCleanup(self.files.close)
        self.files.poll(True)
        self.assertEqual((self.files.health['auth']['invalid'],self.files.health['auth']['status']),(0,'GAP'))
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
