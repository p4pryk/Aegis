import json
import sqlite3
import time
import unittest
from unittest.mock import patch

import release_check


class Continuity(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT)')
        self.now=time.time()
        self.put('heartbeat',{'time':self.now,'pid':123,'boot_id':'boot'})
        self.put('sensor_health',{'time':self.now,'audit':{'enabled':'1','lost':'3'},'audit_spool':{'dropped':2,'rows':0},'sources':[{'name':'Kernel audit','status':'LIVE'},{'name':'SSH journal','status':'QUIET'}]})

    def put(self,key,value):
        self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',(key,json.dumps(value)))

    def test_current_healthy_sample_and_unchanged_counters_pass(self):
        first=release_check.sample(self.db,self.now)
        self.assertTrue(release_check.continuous(first,None))
        self.assertTrue(release_check.continuous(release_check.sample(self.db,self.now+5),first))

    def test_clock_is_sampled_after_database_read(self):
        calls=[]
        class DelayedRead:
            def execute(inner,sql):
                calls.append('read')
                return self.db.execute(sql).fetchall()
        def clock():
            calls.append('clock');return self.now+2
        with patch.object(release_check.time,'time',side_effect=clock):
            item=release_check.sample(DelayedRead())
        self.assertEqual(calls,['read','clock']);self.assertEqual(item['time'],self.now+2);self.assertTrue(item['core_alive'])

    def test_missing_or_disabled_audit_cannot_pass(self):
        for health in ({'time':self.now},{'time':self.now,'audit':{'enabled':'0','lost':'0'},'audit_spool':{'dropped':0}}):
            self.put('sensor_health',health)
            with self.assertRaises(ValueError):release_check.sample(self.db,self.now)

    def test_stale_health_and_collector_restart_fail(self):
        first=release_check.sample(self.db,self.now)
        self.assertFalse(release_check.continuous(release_check.sample(self.db,self.now+16),first))
        for key,value in [('core_pid',124),('boot_id','new-boot')]:
            current=dict(first);current[key]=value
            self.assertFalse(release_check.continuous(current,first))

    def test_counter_increase_or_reset_fails_even_below_initial_value(self):
        first=release_check.sample(self.db,self.now)
        for key in ('spool_dropped','kernel_lost','refused_cases'):
            for change in (-1,1):
                current=dict(first);current[key]=max(0,first[key]+change)
                if current[key]!=first[key]:self.assertFalse(release_check.continuous(current,first))
        self.put('sensor_health',{'time':self.now,'audit':{'enabled':'1','lost':'bad'},'audit_spool':{'dropped':2}})
        with self.assertRaises(ValueError):release_check.sample(self.db,self.now)

    def test_collector_failure_is_not_hidden_by_healthy_core(self):
        health={'time':self.now,'audit':{'enabled':'1','lost':'0'},'audit_spool':{'dropped':0},
                'sources':[{'name':'Kernel audit','status':'QUIET'},{'name':'SSH journal','status':'DOWN'}]}
        self.put('sensor_health',health)
        item=release_check.sample(self.db,self.now)
        self.assertTrue(item['core_alive']);self.assertFalse(release_check.continuous(item,None))
        self.assertEqual(item['unhealthy_sources'],['SSH journal: DOWN'])
        health['sources'][1]['status']='DISABLED';self.put('sensor_health',health)
        self.assertTrue(release_check.continuous(release_check.sample(self.db,self.now),None))
        for status in ('DOWN','DISABLED','GAP','LAGGING','UNKNOWN'):
            health['sources'][0]['status']=status;self.put('sensor_health',health)
            item=release_check.sample(self.db,self.now)
            self.assertFalse(release_check.continuous(item,None));self.assertIn('Kernel audit: '+status,item['unhealthy_sources'])
