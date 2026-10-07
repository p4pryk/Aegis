import json,pathlib,sys,tempfile,time,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent
from journal_sources import parse

class JournalTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.config=dict(agent.DEFAULTS,data_dir=self.tmp.name,journal_units=['aegis-target.service','nginx.service'],web_units=['aegis-target.service'])
        self.store=agent.Store(self.config);self.addCleanup(self.store.db.close)
        self.engine=agent.CorrelatedEngine(self.config,self.store,lambda _:self.fail('unexpected defense action'))
        self.ip='198.51.100.24';self.request_id='a'*32;self.when=time.time()

    def record(self,unit,message,offset=0,comm='python3'):
        return {'_BOOT_ID':self.engine.boot_id,'_SYSTEMD_UNIT':unit,'_COMM':comm,'MESSAGE':message,'__REALTIME_TIMESTAMP':str(int((self.when+offset)*1_000_000)),'__CURSOR':unit+str(offset)}

    def test_http_request_id_joins_broker_case_and_proxy_stays_context(self):
        login=self.engine.normalize('app_login','request',{'request_id':self.request_id,'ip':self.ip,'bypass':True,'success':True},'app:login',self.when)
        self.engine.remember(login);case_id=self.engine.create_or_append('app_sql_login','request',login)
        structured=json.dumps({'event':'aegis_http_access','request_id':self.request_id,'ip':self.ip,'method':'POST','path':'/login','status':200})
        self.engine.journal_context(self.record('aegis-target.service',structured,.01))
        self.assertEqual(len(self.engine.http_request_context(login)),1)

        proxy=self.record('nginx.service',self.ip+' - - [01/Jan/2026:12:00:00 +0000] "POST /login?username=admin%27-- HTTP/1.1" 200 123',.02)
        event=parse(proxy,self.engine.boot_id,self.config)
        self.assertEqual(event['kind'],'http_sqli_signature')
        self.assertEqual(event['details']['path'],'/login')
        self.assertNotIn('admin',json.dumps(event['details']))
        self.engine.journal_context(proxy)
        self.engine.enrich_app_cases()

        case=self.store.db.execute('SELECT id,version FROM cases WHERE id=?',(case_id,)).fetchone()
        snapshot=self.engine.snapshot(case_id,'app_sql_login','request',case[1])
        relations={edge['relation'] for edge in snapshot['edges']}
        self.assertIn('shared_server_generated_request_id',relations)
        self.assertIn('same_ip_and_path_nearby_time_context_not_causal',relations)
        self.assertFalse(snapshot['allowed_actions'])

    def test_sudo_event_keeps_session_metadata_but_not_arguments(self):
        raw=self.record('user@1000.service','labadmin : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/useradd lab_new',comm='sudo')
        raw.update(_COMM='sudo',_AUDIT_SESSION='42',_AUDIT_LOGINUID='1000')
        event=parse(raw,self.engine.boot_id,self.config)
        self.assertEqual(event['kind'],'sudo_command')
        self.assertEqual(event['details']['audit_session'],'42')
        self.assertEqual(event['details']['command'],'useradd')
        self.assertNotIn('lab_new',json.dumps(event['details']))

if __name__=='__main__':unittest.main()
