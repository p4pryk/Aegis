import json,pathlib,sys,tempfile,time,unittest
from unittest.mock import patch,Mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,audit_spool,persistence,telemetry

class Telemetry(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.c=dict(agent.DEFAULTS,data_dir=self.temp.name,persistence_enabled=True)
        self.store=agent.Store(self.c);self.addCleanup(self.store.db.close)
        self.e=agent.CorrelatedEngine(self.c,self.store,lambda _:self.fail('unexpected action'))
        self.now=time.time()

    def record(self,kind,content,offset=0,serial=123):
        self.e.audit_line(f'type={kind} msg=audit({self.now+offset}:{serial}): '+content)

    def login(self,session='42'):
        with patch.object(agent.pwd,'getpwnam',return_value=Mock(pw_uid=1002)),patch.object(agent,'process_snapshot',return_value=None):
            self.record('USER_START',f'pid=100 uid=0 auid=1002 ses={session} msg=\'acct="lab_actor" exe="/usr/sbin/sshd" addr=198.51.100.9 res=success\'',-2)

    def change(self,session='42',offset=0):
        self.record('USER_MGMT',f'pid=200 uid=0 auid=1002 ses={session} msg=\'op="add-user-to-group" acct="lab_actor" grp="sudo" secret="never-keep-me" res=success\'',offset,124)

    def file(self,path,extra='',cwd=None,operation='NORMAL'):
        self.record('SYSCALL','success=yes pid=200 uid=0 auid=1002 ses=42 exe="/usr/bin/chmod" key="aegis_identity"')
        self.record('PATH',f'name="{path}" nametype={operation} mode=0100600 ouid=1002 ogid=1002 '+extra)
        if cwd:self.record('CWD','cwd="'+cwd+'"')
        self.record('EOE','')

    def test_management_metadata_and_spool_selection(self):
        self.change()
        event=self.e.db.execute("SELECT details_json FROM correlation_events WHERE kind='identity_change'").fetchone()[0]
        self.assertIn('add-user-to-group',event);self.assertNotIn('never-keep-me',event)
        for kind in telemetry.RECORDS|{'CWD','1307'}:self.assertTrue(audit_spool.selected('type='+kind+' msg=audit(1:1): x'))
        self.assertTrue(audit_spool.selected('type=SYSCALL msg=audit(1:1): key="aegis_identity"'))
        self.assertFalse(audit_spool.selected('type=EXECVE msg=audit(1:1): secret'))

    def test_failed_or_unprivileged_management_is_not_reported_successful(self):
        for content in ('pid=1 uid=0 msg=\'acct="lab_x" res=failed\'','pid=1 uid=1002 msg=\'acct="lab_x" res=success\''):
            self.record('USER_MGMT',content)
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0],0)

    def test_file_metadata_only_and_relative_path(self):
        self.file('authorized_keys',extra='password="never-keep-me"',cwd='/home/lab_actor/.ssh')
        event=self.e.db.execute('SELECT kind,subject,details_json FROM correlation_events').fetchone()
        self.assertEqual(event[:2],('persistence_change','/home/lab_actor/.ssh/authorized_keys'))
        self.assertEqual(json.loads(event[2])['audited_inode']['mode'],'0100600');self.assertNotIn('never-keep-me',event[2])

    def test_unresolved_relative_and_unwatched_paths_ignored(self):
        self.file('authorized_keys');self.file('/tmp/random')
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0],0)

    def test_new_identity_paths_and_delete_operation_observed(self):
        self.file('/etc/sudoers.d/lab_rule',operation='DELETE')
        event=self.e.db.execute('SELECT kind,details_json FROM correlation_events').fetchone()
        self.assertEqual(event[0],'security_file_change');self.assertEqual(json.loads(event[1])['operation'],'DELETE')
        for path in ('/etc/group','/etc/shadow','/etc/systemd/system/x.service.d/override.conf','/etc/systemd/system/multi-user.target.wants/x.service','/var/spool/cron/crontabs/lab_actor','/etc/cron.daily/lab_task'):
            self.assertIsNotNone(persistence.watched_path(path))
        self.assertIsNone(persistence.watched_path('/etc/../tmp/shadow'))

    def test_late_login_and_sudo_enrich_existing_case_after_restart(self):
        self.change();row=self.e.db.execute('SELECT id,kind,subject FROM cases').fetchone()
        self.e.db.execute('UPDATE cases SET created_at=?',(self.now-180,));self.e.db.commit()
        self.login();self.e=agent.CorrelatedEngine(self.c,self.store,lambda _:self.fail('action'))
        raw={'_BOOT_ID':self.e.boot_id,'_COMM':'sudo','_AUDIT_SESSION':'42','_AUDIT_LOGINUID':'1002','MESSAGE':'lab_actor : USER=root ; COMMAND=/usr/sbin/usermod -aG sudo lab_actor','__CURSOR':'late','__REALTIME_TIMESTAMP':str(int((self.now-1)*1e6))}
        self.e.journal_context(raw);telemetry.enrich(self.e,self.now+3)
        events=self.e.events(row[0]);self.assertEqual({e['kind'] for e in events},{'identity_change','ssh_session_open','sudo_command'})
        snapshot=self.e.snapshot(*row,1);self.assertFalse(snapshot['allowed_actions'])
        self.assertEqual(len(snapshot['edges']),2);self.assertTrue(all('not_causal' in e['relation'] for e in snapshot['edges']))
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM cases').fetchone()[0],1)

    def test_same_ip_other_session_previous_boot_and_unset_ids_never_join(self):
        self.login('41');self.change('42');telemetry.enrich(self.e,self.now+3)
        row=self.e.db.execute('SELECT id FROM cases').fetchone()
        self.assertEqual(len(self.e.events(row[0])),1)
        for d in ({'boot_id':'b','session':'4294967295','auid':'1002'},{'boot_id':'b','session':'1','auid':'4294967295'}):self.assertIsNone(telemetry.identity(d))
        login=self.e.normalize('ssh_session_open','x',{'boot_id':'old','session':'42','auid':'1002'},'old',self.now-1)
        self.assertFalse(telemetry.links([login,*self.e.events(row[0])]))

    def test_partial_file_event_survives_checkpoint(self):
        self.record('SYSCALL','success=yes pid=200 uid=0 auid=1002 ses=42 exe="/usr/bin/chmod" key="aegis_identity"')
        self.record('CWD','cwd="/etc/sudoers.d"')
        self.store.state('audit_assembly',self.e.persistence_pending)
        self.e=agent.CorrelatedEngine(self.c,self.store,None)
        self.record('PATH','name="lab_rule" nametype=NORMAL');self.record('EOE','')
        self.assertEqual(self.e.db.execute('SELECT subject FROM correlation_events').fetchone()[0],'/etc/sudoers.d/lab_rule')

    def test_enrichment_does_not_reopen_defended_case(self):
        self.change();self.login();self.e.db.execute("UPDATE cases SET status='defended'");self.e.db.commit()
        telemetry.enrich(self.e,self.now+3)
        row=self.e.db.execute('SELECT id,status FROM cases').fetchone()
        self.assertEqual(row[1],'defended');self.assertEqual(len(self.e.events(row[0])),1)

    def test_process_link_requires_birth_identity_not_pid_alone(self):
        d={'boot_id':self.e.boot_id,'pid':2,'start_ticks':300,'session':'42','auid':'1002'}
        process=self.e.normalize('process_exec','2',dict(d),'process',self.now-1)
        change=self.e.normalize('security_file_change','/etc/group',dict(d),'change',self.now)
        self.assertEqual(len(telemetry.links([process,change])),1)
        for value in (None,301):
            change['details']['start_ticks']=value
            self.assertFalse(telemetry.links([process,change]))

    def test_distribution_account_change_format_retains_operation_and_numeric_target(self):
        self.record('USER_CHAUTHTOK',"pid=200 uid=0 auid=1002 ses=42 msg='op=changing user shell id=1003 exe=\"/usr/sbin/usermod\" res=success'")
        data=json.loads(self.e.db.execute("SELECT details_json FROM correlation_events WHERE kind='identity_change'").fetchone()[0])
        self.assertEqual(data['op'],'changing user shell');self.assertEqual(data['id'],'1003')

    def test_existing_service_context_remains_available(self):
        self.login();login=self.e.normalize('ssh_session_open','session',{'boot_id':self.e.boot_id,'session':'42','auid':'1002'},'login',self.now-2)
        event=self.e.normalize('service_event','fixture.service',{'boot_id':self.e.boot_id,'audit_session':'42','auid':'1002'},'service',self.now)
        self.e.remember(event)
        self.assertEqual([e['event_id'] for e in telemetry.session_events(self.e,login,self.now+1)],['service'])
