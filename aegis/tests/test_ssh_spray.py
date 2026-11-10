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

    def test_spray_is_retained_across_case_boundary_and_restart(self):
        for n in range(4):self.add('user'+str(n),n)
        original=self.store.db.execute("SELECT id FROM cases WHERE kind='ssh_threshold'").fetchone()[0]
        self.store.db.execute('UPDATE cases SET created_at=? WHERE id=?',(self.now-121,original));self.store.db.commit()
        self.engine=agent.CorrelatedEngine(self.engine.c,self.store,None)
        self.add('user4',4)
        rows=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='ssh_threshold' ORDER BY created_at").fetchall()
        self.assertEqual(len(rows),2);self.assertEqual(rows[0][0],original)
        latest=self.engine.snapshot(*rows[-1])
        self.assertEqual(latest['signals'][0]['distinct_accounts'],5);self.assertFalse(latest['allowed_actions'])

    def test_full_case_rolls_over_without_losing_new_failure(self):
        for n in range(256):self.engine.failure('ssh',self.ip,self.now,'burst-'+str(n),user='same_user')
        self.engine.failure('ssh',self.ip,self.now,'burst-next',user='new_user')
        rows=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='ssh_threshold' ORDER BY created_at").fetchall()
        self.assertEqual(len(rows),2)
        self.assertIn('ssh:burst-next',{event['event_id'] for event in self.engine.events(rows[-1][0])})
        self.assertTrue(all(len(self.engine.events(row[0]))<=256 for row in rows))

    def test_prior_failures_outside_window_are_not_carried_forward(self):
        for n in range(4):self.engine.failure('ssh',self.ip,self.now-121,'old-'+str(n),user='user'+str(n))
        self.store.db.execute("UPDATE cases SET created_at=? WHERE kind='ssh_threshold'",(self.now-121,));self.store.db.commit()
        self.add('user4',4)
        rows=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='ssh_threshold' ORDER BY created_at").fetchall()
        self.assertEqual(len(rows),2);latest=self.engine.snapshot(*rows[-1])
        self.assertEqual(latest['signals'],[]);self.assertFalse(latest['allowed_actions'])

    def test_time_ip_case_and_invalid_names_do_not_inflate_counts(self):
        def event(user,when,ip='192.0.2.25'):
            return {'kind':'ssh_failure','event_time':when,'details':{'ip':ip,'user':user}}
        events=[event('alice',0),event('ALICE',1),event('bob',2),event('carol',3),event('dave',4),event('evil;payload',5),event('other',6,'192.0.2.26'),event('old',-130)]
        self.assertEqual(agent.ssh_spray_signal(events,self.ip),[])
        events.append(event('eve',6));self.assertEqual(agent.ssh_spray_signal(events,self.ip)[0]['distinct_accounts'],5)
        events.append(event('later',200));self.assertEqual(agent.ssh_spray_signal(events,self.ip),[])
