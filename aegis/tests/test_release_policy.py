import json
import unittest
from unittest.mock import Mock, patch
import agent
import policy
import test_correlated as fixtures

class Modes(unittest.TestCase):
    setUp=fixtures.Correlation.setUp
    tearDown=fixtures.Correlation.tearDown
    chain=fixtures.Correlation.chain
    account=fixtures.Correlation.account
    awaiting=fixtures.Correlation.awaiting
    proposal=fixtures.Correlation.proposal
    apply=fixtures.Correlation.apply
    status=fixtures.Correlation.status
    def test_observe_and_review_keep_assessment_without_response(self):
        for mode, status in [('observe','observing'),('review','review_required')]:
            self.c['response_mode']=mode
            self.chain(); row=self.awaiting(); self.apply(row,self.proposal(row))
            self.assertEqual(self.status(row),status)
            self.assertFalse(self.actions)
            self.assertEqual(self.store.db.execute('SELECT count(*) FROM response_runs').fetchone()[0],0)
            self.store.db.execute('DELETE FROM cases');self.store.db.execute('DELETE FROM case_events');self.store.db.execute('DELETE FROM correlation_events');self.store.db.commit()
    def test_default_and_executor_fail_closed(self):
        self.assertEqual(agent.DEFAULTS['response_mode'],'observe')
        for mode in ('observe','review','invalid'):
            with self.assertRaisesRegex(ValueError,'Containment disabled'):
                agent.Executor(dict(self.c,response_mode=mode)).execute({'action':'block_ip','ip':'198.51.100.7'})
    def test_explicit_non_lab_scope_and_protected_groups(self):
        config=dict(response_users=['alice'],protected_users=[],protected_groups=['sudo'])
        with patch.object(policy.pwd,'getpwnam',return_value=Mock(pw_uid=1002,pw_gid=1002)),patch.object(policy.grp,'getgrnam',return_value=Mock(gr_gid=27,gr_mem=[])):
            self.assertTrue(policy.account_allowed('alice',config))
            self.assertFalse(policy.account_allowed('bob',config))
            self.assertFalse(policy.account_allowed('root',config))
        with patch.object(policy.pwd,'getpwnam',return_value=Mock(pw_uid=1002,pw_gid=27)),patch.object(policy.grp,'getgrnam',return_value=Mock(gr_gid=27,gr_mem=[])):
            self.assertFalse(policy.account_allowed('alice',config))
    def test_config_rejects_typo_and_injection(self):
        for config in ({'response_mode':'enfore'},{'response_users':['root;id']},{'protected_groups':'sudo'},{'lab_response_enabled':'false'}):
            with self.assertRaises(ValueError):policy.validate(config)

    def test_protected_networks_cover_both_address_families(self):
        config=dict(self.c,protected_ips=['198.51.100.0/24','2001:db8::/32'])
        self.assertIsNone(agent.safe_ip('198.51.100.7',config))
        self.assertIsNone(agent.safe_ip('::ffff:198.51.100.7',config))
        self.assertIsNone(agent.safe_ip('2001:db8::123',config))
        self.assertEqual(agent.safe_ip('203.0.113.7',config),'203.0.113.7')
    def test_protected_creator_is_not_automatically_benign_in_production(self):
        self.c.update(trust_account_creators=False,ssh_account_creator_allowlist=['operator'])
        self.account()
        with patch.object(agent.pwd,'getpwuid',return_value=Mock(pw_name='operator')):
            row=self.awaiting()
        self.assertEqual(json.loads(row[2])['policy']['actor_authorization'],'not_established')

    def test_review_surfaces_suspicion_without_authorized_actions(self):
        self.c['response_mode']='review';self.account();row=self.awaiting()
        self.apply(row,self.proposal(row));self.assertEqual(self.status(row),'review_required');self.assertFalse(self.actions)
