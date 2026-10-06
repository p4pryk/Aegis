import copy,hashlib,pathlib,sys,tempfile,time,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,persistence
class PersistenceTests(unittest.TestCase):
    def test_suspicious_case_display_without_destructive_action(self):
        from presentation import case_display
        for kind in ('application_shell','persistence_change','app_sql_login'):
            self.assertEqual(case_display({'kind':kind,'status':'insufficient_evidence'})['level'],'warning')
        self.assertEqual(case_display({'kind':'persistence_change','status':'authorized'})['level'],'neutral')
        self.assertEqual(case_display({'kind':'persistence_change','status':'superseded'})['level'],'neutral')
    def test_file_change_is_only_observation_without_attack_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory,persistence_enabled=True,protected_ips=[])
            store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,lambda _:self.fail('unexpected action'))
            stamp=time.time();serial=84721;pid=7321
            snap={'pid':pid,'start_ticks':123,'cgroup':'0::/system.slice/aegis-target-broker.service'}
            lines=[f'type=SYSCALL msg=audit({stamp}:{serial}): success=yes pid={pid} ppid=1 uid=0 auid=4294967295 ses=4294967295 exe="/usr/bin/python3" key="aegis_persistence"',f'type=PATH msg=audit({stamp}:{serial}): item=0 name="/etc/cron.d/lab_aegis_unit" inode=1 nametype=CREATE',f'type=EOE msg=audit({stamp}:{serial}):']
            with patch.object(agent,'process_snapshot',return_value=snap):
                for line in lines:engine.audit_line(line)
            row=store.db.execute("SELECT id,kind FROM cases WHERE kind='persistence_change'").fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(engine.snapshot(row[0],row[1],'/etc/cron.d/lab_aegis_unit',1)['allowed_actions'],[])
            store.db.close()
    def setUp(self):
        self.sid='a'*32;self.path='/etc/cron.d/lab_aegis_test';self.digest=hashlib.sha256(b'test').hexdigest();self.boot='boot'
        def item(kind,t,details):return {'event_id':kind,'event_time':t,'kind':kind,'subject':self.path if kind=='persistence_change' else self.sid,'details':details}
        self.events=[item('app_login',1,{'event_id':'login','bypass':True,'success':True,'session':self.sid,'ip':'10.0.0.2'}),item('persistence_change',2,{'path':self.path,'pid':99,'start_ticks':500,'uid':'0','boot_id':self.boot,'cgroup':'0::/system.slice/aegis-target-broker.service'}),item('app_persistence_job',3,{'path':self.path,'sha256':self.digest,'broker_pid':99,'broker_start_ticks':500,'boot_id':self.boot,'session':self.sid,'login_id':'login','ip':'10.0.0.2'})]
    def test_complete_scoped_chain(self):
        with patch.object(persistence,'fingerprint',return_value=(self.digest,(1,2))):
            actions,ids,edges=persistence.plan(self.events,{},self.boot)
        self.assertEqual([a['action'] for a in actions],['quarantine_persistence','revoke_app_session']);self.assertEqual(len(ids),3);self.assertEqual(len(edges),2)
    def test_missing_or_spoofed_links_withhold_action(self):
        with patch.object(persistence,'fingerprint',return_value=(self.digest,(1,2))):
            for i in range(3):self.assertEqual(persistence.plan(self.events[:i]+self.events[i+1:],{},self.boot)[0],[])
            for i,key,value in [(0,'bypass',False),(0,'session','b'*32),(1,'path','/root/.ssh/authorized_keys'),(1,'pid',98),(1,'start_ticks',501),(1,'uid','1000'),(1,'cgroup','0::/system.slice/other.service'),(2,'path','/etc/crontab'),(2,'login_id','wrong'),(2,'sha256','0'*64)]:
                with self.subTest(key=key):
                    events=copy.deepcopy(self.events);events[i]['details'][key]=value;self.assertEqual(persistence.plan(events,{},self.boot)[0],[])
            self.assertEqual(persistence.plan(self.events,{},'another_boot')[0],[])
    def test_linked_case_supersedes_generic_file_case(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory,protected_ips=[])
            store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,lambda _:self.fail('unexpected action'));engine.boot_id=self.boot
            events=copy.deepcopy(self.events);events[0]['event_id']='app:login';events[2]['event_id']='app:job'
            for event in events:engine.remember(event)
            generic=engine.create_or_append('persistence_change',self.path,events[1])
            with patch.object(persistence,'fingerprint',return_value=(self.digest,(1,2))):persistence.chain(engine,events[2])
            self.assertEqual(store.db.execute('SELECT status FROM cases WHERE id=?',(generic,)).fetchone()[0],'superseded')
            self.assertEqual(store.db.execute("SELECT count(*) FROM cases WHERE kind='app_sql_persistence'").fetchone()[0],1)
            store.db.close()
    def test_file_changed_before_analysis_withholds_action(self):
        with patch.object(persistence,'fingerprint',return_value=('0'*64,(1,2))):self.assertEqual(persistence.plan(self.events,{},self.boot)[0],[])
    def test_only_bounded_paths_can_be_quarantined(self):
        for path in ['/root/.ssh/authorized_keys','/etc/crontab','/etc/cron.d/admin','/etc/systemd/system/sshd.service','/etc/cron.d/lab_aegis_../x']:
            self.assertFalse(persistence.lab_path(path))
            with self.assertRaises(ValueError):persistence.quarantine({'action':'quarantine_persistence','path':path,'sha256':self.digest})
if __name__=='__main__':unittest.main()
