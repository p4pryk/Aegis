import json
import tempfile
import time
import unittest

import agent
import ai_worker
import console


class SSHSuccessContext(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        config=dict(agent.DEFAULTS,data_dir=self.temp.name,response_mode='enforce')
        self.store=agent.Store(config);self.addCleanup(self.store.db.close)
        self.engine=agent.CorrelatedEngine(config,self.store,None);self.now=time.time();self.ip='192.0.2.70'

    def failure(self,user,n,offset=0,ip=None):
        self.engine.failure('ssh',ip or self.ip,self.now+offset,'failure-'+str(n),user=user)

    def latest(self,ip=None):
        row=self.store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='ssh_threshold' AND subject=? ORDER BY created_at DESC LIMIT 1",(ip or self.ip,)).fetchone()
        return self.engine.snapshot(*row)

    def test_success_after_failures_is_visible_and_never_authorizes_block(self):
        for n in range(5):self.failure('alice',n,offset=-2)
        self.engine.ssh_success(self.ip,'alice',self.now,'success')
        evidence=self.latest();self.assertIn({'kind':'ssh_success_after_failures','failure_count':5,'window_seconds':300},evidence['signals'])
        self.assertEqual(evidence['allowed_actions'],[])
        case={'id':'case','kind':'ssh_threshold','version':1,'status':'insufficient_evidence','evidence_json':json.dumps(evidence)}
        self.assertIn('SSH login after 5 failed attempts','\n'.join(console.case_lines({'cases':[case]},120)))
        message=ai_worker.model_messages(case,evidence,{})[-1]['content']
        self.assertIn('<logs>',message);self.assertIn('ssh_success_after_failures',message)
        self.assertIn('does not prove account compromise or authorize a response',ai_worker.SYSTEM)

    def test_correlation_survives_case_boundary_and_restart(self):
        for n in range(5):self.failure('alice',n,offset=-240)
        self.store.db.execute("UPDATE cases SET created_at=? WHERE kind='ssh_threshold'",(self.now-121,));self.store.db.commit()
        self.engine=agent.CorrelatedEngine(self.engine.c,self.store,None)
        self.engine.ssh_success(self.ip,'alice',self.now,'success')
        evidence=self.latest();self.assertEqual(evidence['signals'][0]['failure_count'],5);self.assertFalse(evidence['allowed_actions'])

    def test_other_account_other_ip_old_and_post_login_failures_do_not_join(self):
        for n in range(5):self.failure('alice',n,offset=-301)
        for n in range(5,10):self.failure('Alice',n,offset=-2)
        for n in range(10,15):self.failure('alice',n,offset=-2,ip='192.0.2.71')
        self.engine.ssh_success(self.ip,'alice',self.now,'success')
        self.assertFalse(any(s['kind']=='ssh_success_after_failures' for s in self.latest()['signals']))
        events=[{'kind':'ssh_success','event_id':'success','event_time':self.now,'details':{'ip':self.ip,'user':'alice'}}]
        events.extend({'kind':'ssh_failure','event_id':str(n),'event_time':self.now+1,'details':{'ip':self.ip,'user':'alice'}} for n in range(5))
        self.assertEqual(agent.ssh_success_after_failures(events,self.ip),[])

    def test_duplicate_failure_ids_and_fewer_than_five_do_not_signal(self):
        events=[{'kind':'ssh_success','event_id':'ok','event_time':self.now,'details':{'ip':self.ip,'user':'alice'}}]
        events.extend({'kind':'ssh_failure','event_id':'same','event_time':self.now-1,'details':{'ip':self.ip,'user':'alice'}} for _ in range(8))
        self.assertEqual(agent.ssh_success_after_failures(events,self.ip),[])
        for n in range(4):self.failure('alice',n,offset=-1)
        self.engine.ssh_success(self.ip,'alice',self.now,'success')
        self.assertEqual(self.latest()['signals'],[])

if __name__=='__main__':unittest.main()
