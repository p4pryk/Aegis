import hashlib,json,pathlib,sys,tempfile,time,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent as a

class Correlation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.c=a.DEFAULTS.copy();self.c.update(data_dir=self.tmp.name,ai_results_dir=self.tmp.name,protected_ips=['203.0.113.1'])
        self.store=a.Store(self.c);self.actions=[]
        def execute(request):
            row=self.store.db.execute('SELECT status,analysis_json FROM cases ORDER BY updated_at DESC LIMIT 1').fetchone()
            self.assertEqual(row[0],'recognized');self.assertTrue(json.loads(row[1])['summary'])
            self.actions.append(request);return {'verified':True}
        self.execute=execute;self.e=a.CorrelatedEngine(self.c,self.store,execute)
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def account(self,name='lab_chain',pid=200,serial=3):
        stamp=time.time()
        line=f'type=ADD_USER msg=audit({stamp}:{serial}): pid={pid} uid=0 auid=1000 ses=7 msg=\'op=adding user acct="{name}" res=success\''
        with patch.object(a.pwd,'getpwnam',return_value=Mock(pw_uid=1002)):self.e.audit_line(line)
    def chain(self,cgroup='/system.slice/defense-lab-workload.service',wrong_parent_start=False):
        now=time.time()
        snapshots={100:{'pid':100,'ppid':50,'start_ticks':10,'cgroup':cgroup},50:{'pid':50,'ppid':1,'start_ticks':5,'cgroup':cgroup},200:{'pid':200,'ppid':100,'start_ticks':20,'cgroup':cgroup}}
        with patch.object(a,'process_snapshot',side_effect=lambda pid:snapshots.get(pid)):
            self.e.audit_line(f'type=SYSCALL msg=audit({now}:1): success=yes pid=100 ppid=50 uid=0 auid=1000 ses=7 exe="/usr/bin/dash" key="lab_root_exec"')
            if wrong_parent_start:snapshots[100]['start_ticks']=999
            self.e.audit_line(f'type=SYSCALL msg=audit({now+.001}:2): success=yes pid=200 ppid=100 uid=0 auid=1000 ses=7 exe="/usr/sbin/useradd" key="lab_root_exec"')
        self.account()
    def awaiting(self):
        with patch.object(a.pwd,'getpwnam',return_value=Mock(pw_uid=1002)):
            self.e.tick(time.time()+3)
        return self.store.db.execute('SELECT id,version,evidence_json FROM cases ORDER BY created_at DESC LIMIT 1').fetchone()
    def proposal(self,row,attack=True,confidence=.95,actions=None):
        i,v,evidence=row;data=json.loads(evidence)
        return {'case_id':i,'version':v,'snapshot_hash':hashlib.sha256(evidence.encode()).hexdigest(),'completed_at':time.time(),'status':'complete','analysis':{'summary':'Grouped normalized events describe the observed chain.','uncertainty':'Lab test; initial exploitation is not proven.','attack':attack,'confidence':confidence,'evidence_ids':[x['event_id'] for x in data['events']],'proposed_actions':data['allowed_actions'] if actions is None else actions}}
    def apply(self,row,proposal):
        with patch.object(a.pwd,'getpwnam',return_value=Mock(pw_uid=1002)):self.e.apply_analysis(*row,proposal)
    def status(self,row):return self.store.db.execute('SELECT status FROM cases WHERE id=?',(row[0],)).fetchone()[0]
    def test_actual_numeric_account_commit_race_survives_restart(self):
        stamp=time.time()
        line=f'type=ADD_USER msg=audit({stamp}:21912): pid=20337 uid=0 auid=1000 ses=112 subj=unconfined msg=\'op=adding user id=1001 exe="/usr/sbin/useradd" hostname=? addr=? terminal=? res=success\'\x1dUID="root" AUID="labadmin" ID="unknown(1001)"'
        with patch.object(a.pwd,'getpwuid',side_effect=KeyError):self.e.audit_line(line)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM pending_account_resolution').fetchone()[0],1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM cases').fetchone()[0],0)
        self.e=a.CorrelatedEngine(self.c,self.store,self.execute)
        with patch.object(a.pwd,'getpwuid',return_value=Mock(pw_name='lab_race')),patch.object(a.pwd,'getpwnam',return_value=Mock(pw_uid=1001)):
            self.e.tick(time.time()+.1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM pending_account_resolution').fetchone()[0],0)
        row=self.store.db.execute('SELECT subject FROM cases').fetchone();self.assertEqual(row[0],'lab_race');self.assertFalse(self.actions)
    def test_unresolved_account_not_silently_discarded(self):
        stamp=time.time();line=f'type=ADD_USER msg=audit({stamp}:21913): pid=1 uid=0 auid=1000 ses=1 msg=\'op=adding user id=1999 res=success\''
        with patch.object(a.pwd,'getpwuid',side_effect=KeyError):
            self.e.audit_line(line);self.e.tick(time.time()+6)
        self.assertEqual(self.store.state('last_unresolved_account')['details']['target_uid'],1999)
        self.assertEqual(self.store.db.execute('SELECT kind FROM observations').fetchone()[0],'account_resolution_failed');self.assertFalse(self.actions)
    def test_runtime_rejects_legacy_mode(self):
        config=self.c.copy();config['mode']='legacy_direct'
        with self.assertRaises(ValueError):a.serve_core(config)
    def test_single_account_no_action_after_analysis(self):
        self.account();row=self.awaiting();self.assertEqual(json.loads(row[2])['allowed_actions'],[])
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'insufficient_evidence');self.assertFalse(self.actions)
    def test_real_structural_chain_described_before_defense(self):
        self.chain();row=self.awaiting();data=json.loads(row[2]);self.assertEqual(len(data['events']),3);self.assertEqual(len(data['edges']),2)
        self.assertEqual(data['allowed_actions'],[{'action':'quarantine_account','user':'lab_chain'}]);self.assertFalse(self.actions)
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'defended')
        history=[r[0] for r in self.store.db.execute('SELECT status FROM case_status_history WHERE case_id=? ORDER BY rowid',(row[0],))]
        self.assertLess(history.index('recognized'),history.index('defended'))
    def test_same_time_unrelated_pid_no_causal_action(self):
        self.chain();self.account('lab_unrelated',pid=999,serial=4);row=self.awaiting();self.assertEqual(json.loads(row[2])['allowed_actions'],[])
        self.apply(row,self.proposal(row));self.assertFalse(self.actions)
    def test_pid_reuse_start_ticks_and_wrong_unit_rejected(self):
        self.chain(wrong_parent_start=True);row=self.awaiting();self.assertFalse(json.loads(row[2])['allowed_actions'])
    def test_shell_outside_configured_unit_rejected(self):
        self.chain('/user.slice/session-7.scope');row=self.awaiting();self.assertFalse(json.loads(row[2])['allowed_actions'])
    def test_no_ai_no_defense(self):
        self.chain();row=self.awaiting();self.assertEqual(self.status(row),'awaiting_analysis');self.assertFalse(self.actions)
        self.e.tick(time.time()+100);self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_forged_model_action_not_authorized(self):
        self.account();row=self.awaiting();proposal=self.proposal(row,actions=[{'action':'quarantine_account','user':'lab_chain'}]);self.apply(row,proposal)
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_stale_version_and_hash_rejected(self):
        self.chain();row=self.awaiting();proposal=self.proposal(row);proposal['snapshot_hash']='0'*64;self.apply(row,proposal)
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_target_uid_change_blocks_defense(self):
        self.chain();row=self.awaiting();proposal=self.proposal(row)
        with patch.object(a.pwd,'getpwnam',return_value=Mock(pw_uid=2002)):
            self.e.apply_analysis(*row,proposal)
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_missing_required_evidence_rejected(self):
        self.chain();row=self.awaiting();proposal=self.proposal(row);proposal['analysis']['evidence_ids']=[];self.apply(row,proposal)
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_unverified_executor_result_is_not_success(self):
        self.chain();row=self.awaiting();self.e.execute=lambda action:{'verified':False}
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'recognized')
        self.e.tick(time.time()+6);self.e.tick(time.time()+17)
        self.assertEqual(self.status(row),'defense_error')
    def test_duplicate_model_actions_are_rejected(self):
        self.chain();row=self.awaiting();action=json.loads(row[2])['allowed_actions'][0]
        self.apply(row,self.proposal(row,actions=[action,action]));self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_low_confidence_observes(self):
        self.chain();row=self.awaiting();self.apply(row,self.proposal(row,confidence=.84));self.assertEqual(self.status(row),'observing');self.assertFalse(self.actions)
    def test_group_survives_restart(self):
        now=time.time()
        for n in range(3):self.e.failure('ssh','198.51.100.9',now,str(n),user='lab_test')
        self.e=a.CorrelatedEngine(self.c,self.store,self.execute);row=self.awaiting();self.assertEqual(len(json.loads(row[2])['events']),3)
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'insufficient_evidence');self.assertFalse(self.actions)
    def test_many_failed_logins_never_allow_ip_block(self):
        now=time.time()
        for n in range(12):self.e.failure('ssh','198.51.100.9',now,str(n),user='lab_test')
        row=self.awaiting();self.assertEqual(json.loads(row[2])['allowed_actions'],[])
        self.apply(row,self.proposal(row));self.assertFalse(self.actions)
    def test_failures_then_success_do_not_prove_compromise(self):
        now=time.time()
        for n in range(5):self.e.failure('ssh','198.51.100.9',now,str(n),user='lab_test')
        self.e.ssh_success('198.51.100.9','lab_test',now+.01,'success',pid=900)
        row=self.awaiting();data=json.loads(row[2]);self.assertEqual(len(data['events']),6)
        self.assertEqual(data['allowed_actions'],[]);self.apply(row,self.proposal(row));self.assertFalse(self.actions)
    def test_model_cannot_block_ip_for_signatures(self):
        now=time.time()
        for n in range(3):self.e.failure('ssh','198.51.100.9',now,str(n),user='lab_test')
        row=self.awaiting();self.apply(row,self.proposal(row,actions=[{'action':'block_ip','ip':'198.51.100.9'}]))
        self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_old_threshold_snapshot_cannot_execute_after_policy_change(self):
        now=time.time()
        for n in range(3):self.e.failure('ssh','198.51.100.9',now,str(n),user='lab_test')
        row=self.awaiting();data=json.loads(row[2]);data['allowed_actions']=[{'action':'block_ip','ip':'198.51.100.9'}]
        data['required_evidence_ids']=[e['event_id'] for e in data['events']]
        evidence=a.canonical(data);row=(row[0],row[1],evidence)
        self.store.db.execute('UPDATE cases SET evidence_json=? WHERE id=?',(evidence,row[0]));self.store.db.commit()
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'analysis_error');self.assertFalse(self.actions)
    def test_new_evidence_invalidates_model_snapshot(self):
        now=time.time()
        for n in range(3):self.e.failure('ssh','198.51.100.9',now,str(n),user='lab_test')
        row=self.awaiting();proposal=self.proposal(row);self.e.failure('ssh','198.51.100.9',now,'four',user='lab_test');self.apply(row,proposal)
        self.assertFalse(self.actions);self.assertEqual(self.status(row),'collecting')
    def test_future_stale_proposal_no_defense(self):
        self.chain();row=self.awaiting();proposal=self.proposal(row);proposal['completed_at']=time.time()-31;self.apply(row,proposal);self.assertFalse(self.actions)

if __name__=='__main__':unittest.main()
