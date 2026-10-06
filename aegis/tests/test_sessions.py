import json,pathlib,sys,time,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent as a
import test_correlated as fixtures

class SSHSessions(unittest.TestCase):
    def setUp(self):
        fixtures.Correlation.setUp(self);self.c['protected_users']=list(self.c['protected_users'])
    tearDown=fixtures.Correlation.tearDown
    awaiting=fixtures.Correlation.awaiting
    proposal=fixtures.Correlation.proposal
    status=fixtures.Correlation.status
    def names(self,name):return Mock(pw_uid=1002 if name=='lab_actor' else 1003)
    def build(self,session='42',failuser='lab_actor',failures=5,login=True,approved=False,dedicated=True):
        self.c.update(ssh_response_users=['lab_actor'],ssh_account_creator_allowlist=['lab_actor'] if approved else ['labadmin'],ssh_dedicated_source_ips=['198.51.100.9'] if dedicated else [])
        now=time.time()
        for n in range(failures):self.e.failure('ssh','198.51.100.9',now-.5,str(n),user=failuser)
        with patch.object(a.pwd,'getpwnam',side_effect=self.names),patch.object(a,'process_snapshot',return_value={'pid':200,'ppid':100,'start_ticks':10,'cgroup':'/user.slice'}):
            if login:self.e.audit_line(f'type=USER_START msg=audit({now-.2}:1): pid=100 uid=0 auid=1002 ses=42 msg=\'op=PAM:session_open acct="lab_actor" exe="/usr/sbin/sshd" addr=198.51.100.9 terminal=ssh res=success\'')
            self.e.audit_line(f'type=SYSCALL msg=audit({now-.1}:2): success=yes pid=200 ppid=100 uid=0 auid=1002 ses={session} exe="/usr/sbin/useradd" key="lab_root_exec"')
            self.e.audit_line(f'type=ADD_USER msg=audit({now}:3): pid=200 uid=0 auid=1002 ses={session} msg=\'op=adding user acct="lab_added" res=success\'')
            self.e.tick(now+3)
        return self.store.db.execute("SELECT id,version,evidence_json FROM cases WHERE kind IN ('ssh_session_account','web_shell_account') ORDER BY created_at DESC LIMIT 1").fetchone()
    def apply(self,row,result):
        with patch.object(a.pwd,'getpwnam',side_effect=self.names):self.e.apply_analysis(*row,result)
    def test_failure_login_account_chain_allows_scoped_response(self):
        row=self.build();data=json.loads(row[2]);self.assertEqual(len(data['events']),8)
        self.assertEqual([x['action'] for x in data['allowed_actions']],['quarantine_account','terminate_session','block_ip'])
        self.assertTrue(any(e['relation']=='same_boot_audit_session_and_loginuid' for e in data['edges']))
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'defended');self.assertEqual(len(self.actions),3)
    def test_other_audit_session_not_attributed_to_ip(self):
        row=self.build(session='99');self.assertFalse(json.loads(row[2])['allowed_actions']);self.assertFalse(self.actions)
    def test_other_username_failures_are_not_counted(self):
        row=self.build(failuser='lab_other');self.assertEqual([a['action'] for a in json.loads(row[2])['allowed_actions']],['quarantine_account','terminate_session'])
    def test_approved_admin_account_creation_is_observation(self):
        row=self.build(approved=True);self.assertFalse(json.loads(row[2])['allowed_actions'])
    def test_known_approved_actor_cannot_be_accused_by_model(self):
        row=self.build(approved=True);self.apply(row,self.proposal(row,attack=True))
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_approved_activity_has_distinct_authorized_state(self):
        row=self.build(approved=True);self.apply(row,self.proposal(row,attack=False))
        self.assertEqual(self.status(row),'authorized');self.assertFalse(self.actions)
    def test_missing_login_proof_cannot_respond(self):
        row=self.build(login=False);self.assertFalse(json.loads(row[2])['allowed_actions'])
    def test_shared_source_does_not_allow_ip_block(self):
        row=self.build(dedicated=False);self.assertEqual([x['action'] for x in json.loads(row[2])['allowed_actions']],['quarantine_account','terminate_session'])
    def test_confirmed_unauthorized_change_without_failures_is_contained_but_ip_not_blocked(self):
        row=self.build(failures=0);self.assertEqual([a['action'] for a in json.loads(row[2])['allowed_actions']],['quarantine_account','terminate_session'])
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'defended')
    def test_closed_session_preserves_evidence_and_containment(self):
        row=self.build();proposal=self.proposal(row)
        self.e.db.execute('UPDATE ssh_sessions SET active=0');self.e.db.commit()
        self.apply(row,proposal);self.assertEqual(self.status(row),'defended');self.assertEqual(len(self.actions),3)
    def test_second_account_in_same_session_gets_own_case(self):
        self.build()
        with patch.object(a.pwd,'getpwnam',side_effect=self.names):
            stamp=time.time();self.e.audit_line(f'type=ADD_USER msg=audit({stamp}:4): pid=200 uid=0 auid=1002 ses=42 msg=\'op=adding user acct="lab_second" res=success\'')
        cases=self.e.db.execute("SELECT id FROM cases WHERE kind='ssh_session_account'").fetchall()
        self.assertEqual(len(cases),2)
        targets=[e['subject'] for row in cases for e in self.e.events(row[0]) if e['kind']=='account_created']
        self.assertCountEqual(targets,['lab_added','lab_second'])
    def test_enrichment_of_defended_account_is_idempotent(self):
        row=self.build();self.apply(row,self.proposal(row));before=self.e.db.execute('SELECT count(*) FROM cases').fetchone()[0]
        self.e.enrich_ssh_accounts();self.e.db.commit()
        self.assertEqual(self.e.db.execute('SELECT count(*) FROM cases').fetchone()[0],before)
        self.assertEqual(self.status(row),'defended');self.assertEqual(len(self.actions),3)
    def test_session_context_survives_restart(self):
        row=self.build();self.e=a.CorrelatedEngine(self.c,self.store,self.execute)
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'defended')
    def test_protected_actor_revokes_actions(self):
        row=self.build();self.c['protected_users'].append('lab_actor')
        self.apply(row,self.proposal(row));self.assertFalse(self.actions)
    def test_model_cannot_block_shared_source(self):
        row=self.build(dedicated=False);self.apply(row,self.proposal(row,actions=[dict(action='block_ip',ip='198.51.100.9')]))
        self.assertFalse(self.actions);self.assertEqual(self.status(row),'analysis_error')
    def test_previous_boot_revokes_pending_proposal(self):
        row=self.build();proposal=self.proposal(row);self.e.boot_id='new-boot'
        self.apply(row,proposal);self.assertFalse(self.actions)
    def test_lab_enrollment_requires_explicit_setting(self):
        self.assertFalse(a.ssh_response_user('lab_new',{}))
        self.assertTrue(a.ssh_response_user('lab_new',{'ssh_lab_users_enabled':True}))
        self.assertFalse(a.ssh_response_user('administrator',{'ssh_lab_users_enabled':True}))
    def test_executor_rejects_unauthorized_session_user(self):
        e=a.Executor(self.c)
        with patch.object(a.pwd,'getpwnam',return_value=Mock(pw_uid=1002)):
            with self.assertRaises(ValueError):e.execute(dict(action='terminate_session',boot_id=self.e.boot_id,session=42,auid=1002,user='lab_actor'))
    def test_wrong_uid_or_unset_session_rejected(self):
        with self.assertRaises(ValueError):a.audit_processes(self.e.boot_id,4294967295,1002)
        with self.assertRaises(ValueError):a.audit_processes(self.e.boot_id,42,0)
if __name__=='__main__':unittest.main()
