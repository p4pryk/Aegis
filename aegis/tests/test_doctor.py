import json
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import doctor

class Doctor(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.config=self.root/'config.json';self.model=self.root/'ai.json';self.db=self.root/'incidents.db';self.now=1000
        self.config.write_text(json.dumps({'response_mode':'observe','auto_access_logs':False}))
        self.model.write_text(json.dumps({'endpoint':'https://example.invalid/SECRET_VALUE','deployment':'SECRET_DEPLOYMENT'}))
        self.put('heartbeat',{'time':self.now,'pid':123,'boot_id':'boot'})
        self.put('sensor_health',{'time':self.now,'sources':[{'name':'Kernel audit','status':'LIVE'},{'name':'SSH journal','status':'QUIET'}]})
        self.put('model_health',{'time':self.now,'status':'IDLE'})
    def put(self,key,value):
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT)')
            db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',(key,json.dumps(value)))
    def run_doctor(self):return doctor.diagnose(self.config,self.model,self.db,self.now)
    def test_healthy_is_read_only_and_does_not_disclose_model_configuration(self):
        before=self.db.read_bytes();result=self.run_doctor()
        self.assertTrue(result['healthy']);self.assertEqual(self.db.read_bytes(),before)
        encoded=json.dumps(result);self.assertNotIn('SECRET_VALUE',encoded);self.assertNotIn('SECRET_DEPLOYMENT',encoded)
        self.assertIn('not tested',encoded)
    def test_missing_model_and_database_are_not_reported_healthy(self):
        self.model.unlink();self.db.unlink();result=self.run_doctor();self.assertFalse(result['healthy'])
        self.assertFalse(self.db.exists());statuses={v['name']:v['status'] for v in result['checks']}
        self.assertEqual(statuses['Model configuration'],'WARN');self.assertEqual(statuses['Collector'],'UNKNOWN')
    def test_stale_and_down_sources_are_not_healthy(self):
        self.put('sensor_health',{'time':self.now,'sources':[{'name':'Kernel audit','status':'LIVE'},{'name':'SSH journal','status':'DOWN'}]})
        self.assertIn('SSH journal: DOWN',json.dumps(self.run_doctor()))
        self.put('heartbeat',{'time':self.now-30});result=self.run_doctor()
        self.assertIn('Core heartbeat missing or stale',json.dumps(result));self.assertFalse(result['healthy'])
    def test_invalid_values_are_never_echoed(self):
        self.config.write_text('{"response_mode":"SECRET_VALUE"}');self.model.write_text('{"endpoint":"SECRET_VALUE"}')
        result=self.run_doctor();self.assertFalse(result['healthy']);self.assertNotIn('SECRET_VALUE',json.dumps(result))
    def test_disabled_optional_sources_do_not_mask_missing_kernel_audit(self):
        self.put('sensor_health',{'time':self.now,'sources':[{'name':'SSH journal','status':'DISABLED'}]})
        self.assertFalse(self.run_doctor()['healthy']);self.assertIn('unavailable',json.dumps(self.run_doctor()))
    def test_budget_reservation_is_visible_without_network(self):
        self.put('model_health',{'time':self.now,'status':'RESPONSE BUDGET RESERVED'})
        with patch('urllib.request.urlopen',side_effect=AssertionError('network forbidden')),patch('ai_worker.token',side_effect=AssertionError('network forbidden')):
            result=self.run_doctor()
        self.assertFalse(result['healthy']);self.assertIn('RESPONSE BUDGET RESERVED',json.dumps(result))

    def test_untrusted_source_name_cannot_inject_terminal_output(self):
        self.put('sensor_health',{'time':self.now,'sources':[{'name':'Kernel audit','status':'LIVE'},{'name':'bad\u001b[31m','status':'DOWN'}]})
        result=self.run_doctor();self.assertFalse(result['healthy'])
        self.assertNotIn('bad',json.dumps(result));self.assertIn('source status unavailable',json.dumps(result))

    def test_http_model_endpoint_is_not_reported_configured(self):
        self.model.write_text(json.dumps({'endpoint':'http://example.invalid','deployment':'example'}))
        result=self.run_doctor();self.assertFalse(result['healthy'])
        self.assertEqual(next(c['status'] for c in result['checks'] if c['name']=='Model configuration'),'UNKNOWN')
