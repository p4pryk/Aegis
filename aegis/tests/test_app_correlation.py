import copy,pathlib,sys,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from app_correlation import plan
class ApplicationPlanTests(unittest.TestCase):
    def setUp(self):
        self.sid='a'*32;self.config={'protected_users':['root','labadmin'],'protected_ips':[],'app_dedicated_source_ips':[]}
        def event(kind,time,details):return dict(event_id=kind,event_time=time,kind=kind,subject='lab_http_test' if kind=='account_created' else self.sid,details=details)
        self.events=[event('app_login',1,dict(event_id='login',bypass=True,success=True,session=self.sid,ip='10.252.79.2')),event('app_account_job',4,dict(login_id='login',session=self.sid,ip='10.252.79.2',user='lab_http_test',pid=99,account_uid=1001,broker_pid=10,broker_start_ticks=500,boot_id='boot')),event('process_exec',2,dict(pid=99,ppid=10,parent_start_ticks=500,uid='0',cgroup='0::/system.slice/aegis-target-broker.service',exe='/usr/sbin/useradd',boot_id='boot',auid='4294967295',session='4294967295')),event('account_created',3,dict(pid=99,account_uid=1001,boot_id='boot',auid='4294967295',session='4294967295'))]
        self.patch=patch('app_correlation.pwd.getpwnam',return_value=types.SimpleNamespace(pw_uid=1001));self.patch.start();self.addCleanup(self.patch.stop)
    def test_complete_default_plan(self):
        actions,required,edges=plan(self.events,self.config);self.assertEqual([a['action'] for a in actions],['quarantine_account','revoke_app_session']);self.assertEqual(len(required),4);self.assertEqual(len(edges),3)
    def test_dedicated_source_only(self):
        self.config['app_dedicated_source_ips']=['10.252.79.2'];self.assertEqual(plan(self.events,self.config)[0][-1]['action'],'block_ip')
    def test_protected_source_never_blocked(self):
        self.config.update(app_dedicated_source_ips=['10.252.79.2'],protected_ips=['10.252.79.2']);self.assertEqual(len(plan(self.events,self.config)[0]),2)
    def test_previous_boot(self):
        self.assertEqual(plan(self.events,self.config,'other_boot')[0],[])
    def test_wrong_unit(self):
        self.events[2]['details']['cgroup']='0::/system.slice/other.service';self.assertEqual(plan(self.events,self.config)[0],[])
    def test_missing_evidence(self):
        for i in range(4):self.assertEqual(plan(self.events[:i]+self.events[i+1:],self.config)[0],[])
    def test_mismatched_links_fail_closed(self):
        for index,key,value in [(0,'bypass',False),(0,'success',False),(0,'session','b'*32),(1,'login_id','wrong'),(1,'ip','10.2.3.4'),(1,'pid',98),(1,'account_uid',1002),(1,'user','lab_http_other'),(2,'ppid',11),(2,'parent_start_ticks',501),(2,'uid','1000'),(2,'exe','/usr/bin/echo'),(3,'auid','1000'),(3,'boot_id','other')]:
            with self.subTest(key=key,index=index):
                events=copy.deepcopy(self.events);events[index]['details'][key]=value;self.assertEqual(plan(events,self.config)[0],[])
    def test_account_uid_reused(self):
        with patch('app_correlation.pwd.getpwnam',return_value=types.SimpleNamespace(pw_uid=1002)):self.assertEqual(plan(self.events,self.config)[0],[])
    def test_event_time_order(self):
        events=copy.deepcopy(self.events);events[0]['event_time']=9;self.assertEqual(plan(events,self.config)[0],[])
if __name__=='__main__':unittest.main()
