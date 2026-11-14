import json,pathlib,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,application_sources
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

    def test_web_context_excludes_other_services_even_under_noise(self):
        self.config['web_units']=['nginx.service','apache2.service']
        lineage=[self.engine.normalize('process_exec','pid',{'cgroup':'0::/system.slice/nginx.service'},'proc',self.when-3)]
        matching=self.engine.normalize('http_sqli_signature',self.ip,{'boot_id':self.engine.boot_id,'unit':'nginx.service'},'same-service',self.when-2)
        self.engine.remember(matching)
        rows=[]
        for n in range(80):
            details={'boot_id':self.engine.boot_id,'unit':'apache2.service'}
            rows.append(('other:'+str(n),self.when-.1,'http_sqli_signature',self.ip,json.dumps(details)))
        rows.append(('old-boot',self.when-.1,'http_sqli_signature',self.ip,json.dumps({'boot_id':'old','unit':'nginx.service'})))
        rows.append(('no-unit',self.when-.1,'http_sqli_signature',self.ip,json.dumps({'boot_id':self.engine.boot_id})))
        self.store.db.executemany('INSERT INTO correlation_events VALUES (?,?,?,?,?)',rows);self.store.db.commit()
        context=self.engine.web_context_events(lineage,self.when)
        self.assertEqual([event['event_id'] for event in context],['same-service'])
        self.config['web_context_units']={'nginx.service':['apache2.service']}
        context=self.engine.web_context_events(lineage,self.when)
        self.assertEqual(context[0]['event_id'],'same-service')
        self.assertEqual(len(context),64)
        self.assertTrue(all(event['details']['unit'] in ('nginx.service','apache2.service') for event in context))
        self.assertTrue(any(event['details']['unit']=='apache2.service' for event in context))
        account=self.engine.normalize('account_created','lab_target',{'account_uid':2000},'account',self.when)
        identifier=self.engine.create_or_append('web_shell_account','lab_target',account,[*lineage,*context])
        row=self.store.db.execute('SELECT id,kind,subject,version FROM cases WHERE id=?',(identifier,)).fetchone()
        with patch.object(self.engine,'lineage',return_value=lineage):evidence=self.engine.snapshot(*row)
        self.assertFalse(evidence['allowed_actions'])
        self.assertTrue(all(edge['relation']=='nearby_http_time_context_not_causal' for edge in evidence['edges']))
        self.assertTrue(any(edge['from'].startswith('other:') for edge in evidence['edges']))

    def test_both_http_adapters_handle_bounded_encoding_and_benign_double_hyphens(self):
        targets=(('/search?q=union%252F%252A%252A%252Fselect',True),('/login?q=%2527%2520or%25201%253D1',True),('/search?q=union+all+select',True),('/search?q=pg_sleep%25281%2529',True),('/search?id=1--&next=2',True),('/search--catalog?name=release--notes',False),('/search?q=ordinary',False))
        source={'name':'access','application':'app','format':'jsonl'}
        for target,expected in targets:
            with self.subTest(target=target):
                msg=self.ip+' - - [01/Jan/2026:12:00:00 +0000] "GET '+target+' HTTP/1.1" 200 123'
                journal=parse(self.record('nginx.service',msg),self.engine.boot_id,self.config)
                app=application_sources.parse(json.dumps({'time':self.when,'event':'http_request','ip':self.ip,'method':'GET','path':target,'status':200}),source,'fixture')
                self.assertEqual(journal['kind']=='http_sqli_signature',expected)
                self.assertEqual(app['details']['sqli_signature'],expected)
                self.assertNotIn(target,json.dumps(journal['details']))
                self.assertNotIn(target,json.dumps(app['details']))
        self.engine.journal_context(self.record('nginx.service',self.ip+' - - [01/Jan/2026:12:00:00 +0000] "GET /?q=union%252F%252A%252A%252Fselect HTTP/1.1" 200 123'))
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='waf_threshold'").fetchone()
        self.assertIsNotNone(row);self.assertFalse(self.engine.snapshot(*row)['allowed_actions'])

if __name__=='__main__':unittest.main()
