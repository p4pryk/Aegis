import json
import tempfile
import time
import unittest

import agent
import ai_worker
import console


class SSHPasswordSpray(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        config=dict(agent.DEFAULTS,data_dir=self.tmp.name,response_mode='enforce')
        self.store=agent.Store(config);self.addCleanup(self.store.db.close)
        self.engine=agent.CorrelatedEngine(config,self.store,None)
        self.now=time.time();self.ip='192.0.2.25'

    def add(self,user,n):
        self.engine.failure('ssh',self.ip,self.now+n/10,'spray-'+str(n),user=user)

    def snapshot(self):
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='ssh_threshold'").fetchone()
        return self.engine.snapshot(*row)

    def test_five_accounts_signal_review_without_containment(self):
        for n in range(5):self.add('user'+str(n),n)
        evidence=self.snapshot();self.assertEqual(evidence['signals'],[{'kind':'possible_ssh_password_spray','distinct_accounts':5,'window_seconds':120}])
        self.assertEqual(evidence['allowed_actions'],[])
        row={'id':'test','kind':'ssh_threshold','version':1,'evidence_json':json.dumps(evidence),'status':'insufficient_evidence'}
        rendered='\n'.join(console.case_lines({'cases':[row]},120))
        self.assertIn('Possible SSH password spraying: 5 accounts',rendered)
        messages=ai_worker.model_messages(row,evidence,{})
        self.assertIn('possible_ssh_password_spray',messages[-1]['content'])
        self.assertIn('not proof of compromise or authorization',ai_worker.SYSTEM)

    def test_repeated_account_does_not_reach_distinct_threshold(self):
        for n in range(8):self.add('same_user',n)
        self.assertEqual(self.snapshot()['signals'],[])

    def test_time_ip_case_and_invalid_names_do_not_inflate_counts(self):
        def event(user,when,ip='192.0.2.25'):
            return {'kind':'ssh_failure','event_time':when,'details':{'ip':ip,'user':user}}
        events=[event('alice',0),event('ALICE',1),event('bob',2),event('carol',3),event('dave',4),event('evil;payload',5),event('other',6,'192.0.2.26'),event('old',-130)]
        self.assertEqual(agent.ssh_spray_signal(events,self.ip),[])
        events.append(event('eve',6));self.assertEqual(agent.ssh_spray_signal(events,self.ip)[0]['distinct_accounts'],5)
        events.append(event('later',200));self.assertEqual(agent.ssh_spray_signal(events,self.ip),[])
