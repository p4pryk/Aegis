import os,pathlib,stat,sys,threading,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import coverage_check as coverage,console

class Coverage(unittest.TestCase):
    def setUp(self):
        self.facts=dict(services={},services_available=True,rules=['lab_root_exec','aegis_identity','aegis_persistence'])
        self.health=dict(time=100,sources=[dict(name=n,status='QUIET',reason='Alive; quiet') for n in ('Kernel audit','SSH journal','Service journal')],system_log_coverage=dict(mode='journal',enabled=True))
    def assess(self,c=None,files=None):
        return coverage.assess(c or {},self.health,self.facts,lambda p:(files or {}).get(p,{'kind':'missing'}),100)
    def test_running_database_is_not_inferred_covered_by_service_journal(self):
        self.facts['services']['postgresql.service']=dict(LoadState='loaded',ActiveState='active')
        row=next(r for r in self.assess()['rows'] if r['name']=='PostgreSQL')
        self.assertEqual(row['status'],'NEEDS CONFIG');self.assertIn('JSONL',row['next_step'])
    def test_nginx_journal_configuration_does_not_cover_http_file(self):
        self.facts['services']['nginx.service']=dict(LoadState='loaded',ActiveState='active')
        report=self.assess({'journal_units':['nginx.service']})
        self.assertEqual(next(r['status'] for r in report['rows'] if r['name']=='Nginx'),'NEEDS CONFIG')
    def test_quiet_custom_file_and_parsed_file_are_distinct(self):
        c={'application_sources':[dict(name='custom',application='custom',path='/logs/custom',format='jsonl')]}
        files={'/logs/custom':dict(kind='file',uid=0,mode=stat.S_IFREG|0o600)}
        self.assertEqual(self.assess(c,files)['rows'][-1]['status'],'CONFIGURED')
        self.health['sources'].append(dict(name='App custom',status='QUIET',parsed=1))
        self.assertEqual(self.assess(c,files)['rows'][-1]['status'],'OBSERVED')
        self.health['sources'][-1]['unrecognized']=1
        self.assertEqual(self.assess(c,files)['rows'][-1]['status'],'FORMAT REVIEW')
    def test_missing_symlink_owner_and_permissions_never_mark_covered(self):
        c={'application_sources':[dict(name='custom',path='/logs/custom',format='jsonl')]}
        for info,wanted in (({'kind':'missing'},'MISSING'),({'kind':'unsafe'},'UNSAFE'),({'kind':'unknown'},'UNKNOWN'),(dict(kind='file',uid=2,mode=0o600),'UNSAFE'),(dict(kind='file',uid=0,mode=0o666),'UNSAFE')):
            with self.subTest(info=info):self.assertEqual(self.assess(c,{'/logs/custom':info})['rows'][-1]['status'],wanted)
    def test_known_directory_with_one_adapter_is_only_partial(self):
        c={'application_sources':[dict(name='db',path='/var/log/postgresql/export.jsonl',format='jsonl')]}
        files={'/var/log/postgresql':{'kind':'directory'},'/var/log/postgresql/export.jsonl':dict(kind='file',uid=0,mode=0o600)}
        self.assertEqual(next(r['status'] for r in self.assess(c,files)['rows'] if r['name']=='PostgreSQL'),'PARTIAL')
    def test_missing_rules_disabled_system_and_unavailable_inventory_are_explicit(self):
        self.facts.update(rules=[],services_available=False);self.health['system_log_coverage']['enabled']=False
        report=self.assess({'persistence_enabled':True});text=str(report)
        self.assertIn('RULES MISSING',text);self.assertIn('aegis_persistence',text);self.assertIn('DISABLED',text);self.assertIn('Service discovery',text)
        self.facts['rules']=None
        self.assertEqual(next(r['status'] for r in self.assess()['rows'] if r['name']=='Selected audit rules'),'UNKNOWN')
    def test_inventory_parses_metadata_only_and_does_not_expose_rule_contents(self):
        with patch.object(coverage,'command',side_effect=['Id=nginx.service\nLoadState=loaded\nActiveState=active\n','-w /secret-file -p wa -k aegis_identity\n-a always,exit -S execve -F key=lab_root_exec']):
            facts=coverage.inventory()
        self.assertEqual(facts['rules'],['aegis_identity','lab_root_exec']);self.assertNotIn('secret-file',str(facts))
    def test_probe_never_blocks_intake_or_spawns_duplicate_worker(self):
        started=threading.Event();release=threading.Event();probe=coverage.Probe({})
        def slow():started.set();release.wait(3);return self.facts
        with patch.object(coverage,'inventory',side_effect=slow) as inventory:
            try:
                self.assertEqual(probe.poll(self.health,100),{});self.assertTrue(started.wait(1))
                thread=probe.thread;probe.poll(self.health,1000);self.assertIs(probe.thread,thread);self.assertEqual(inventory.call_count,1)
            finally:release.set();probe.thread.join(2)
        self.assertTrue(probe.result['rows'])
    def test_stale_core_does_not_display_old_ready_states(self):
        report=self.assess()
        self.assertIn('stale',' '.join(coverage.lines(report,100,100,False)))
        self.assertIn('stale',' '.join(coverage.lines(report,100,221)))
        self.assertNotIn('[READY]',' '.join(coverage.lines(report,100,221)))
    def test_metadata_does_not_open_fifo_or_follow_symlinks(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            fifo=pathlib.Path(tmp)/'fifo';os.mkfifo(fifo)
            link=pathlib.Path(tmp)/'link';link.symlink_to(fifo)
            for p in (fifo,link):self.assertEqual(coverage.metadata(p)['kind'],'unsafe')
    def test_collector_gaps_remain_review_items(self):
        self.health['sources'][0]['status']='GAP'
        report=self.assess();self.assertEqual(report['gaps'],1)
        self.assertTrue(any(getattr(line,'level',None)=='warning' and '[GAP]' in line for line in coverage.lines(report,104,100)))
    def test_source_screen_safely_renders_report(self):
        report=self.assess();report['rows'][0]['name']='test\x1b[2J'
        self.health['coverage_check']=report
        lines=console.source_lines({'sensor_health':self.health},104,100)
        self.assertIn('COVERAGE CHECK',' '.join(lines));self.assertNotIn('\x1b',' '.join(lines))
        self.assertTrue(all(console.cells(line)<=104 for line in lines))

if __name__=='__main__':unittest.main()
