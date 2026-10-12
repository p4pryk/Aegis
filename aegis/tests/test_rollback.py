import json,os,pathlib,sys,tempfile,time,unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import rollback as r

class Rollback(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.j=r.Journal({'data_dir':tmp.name,'protected_users':['root']})
        self.boot=patch.object(r,'boot',return_value='boot');self.boot.start();self.addCleanup(self.boot.stop)
        self.network=None
        p=patch.object(r,'ip_state',side_effect=lambda ip:self.network);p.start();self.addCleanup(p.stop)
        self.executor=Mock();self.executor.c={'block_seconds':600}
        def block(request,undo_token=None):
            if self.network is None:self.network={'comment':'aegis-undo-'+undo_token}
            return {'verified':True}
        self.executor.execute.side_effect=block
    def receipt(self):
        out=self.j.record(self.executor,{'action':'block_ip','ip':'198.51.100.44'})
        return out['undo_receipt']
    def test_owned_block_plan_and_idempotent_undo(self):
        identifier=self.receipt();plan=self.j.plan(identifier)
        with patch('agent.run',side_effect=lambda args:setattr(self,'network',None)) as run:
            self.assertTrue(self.j.apply(identifier,plan['confirmation'],'False positive')['verified'])
            self.assertTrue(self.j.apply(identifier,'','Repeat')['already_restored'])
            run.assert_called_once()
        self.assertEqual(self.j.read(identifier)['history'][-1]['reason'],'False positive')
    def test_foreign_block_and_duplicate_claim_cannot_be_removed(self):
        first=self.receipt();second=self.receipt()
        self.assertFalse(self.j.read(second)['eligible'])
        with self.assertRaisesRegex(ValueError,'Another containment'):self.j.plan(first)
    def test_replaced_block_is_not_removed(self):
        identifier=self.receipt();plan=self.j.plan(identifier);self.network={'comment':'other-owner'}
        with self.assertRaisesRegex(ValueError,'ownership'):self.j.apply(identifier,plan['confirmation'],'Review')
        self.assertEqual(self.j.read(identifier)['history'][-1]['state'],'refused')
    def test_absent_block_is_verified_noop(self):
        identifier=self.receipt();self.network=None;plan=self.j.plan(identifier)
        with patch('agent.run') as run:
            self.j.apply(identifier,plan['confirmation'],'Already expired');run.assert_not_called()
    def test_boot_change_and_stale_confirmation_refused(self):
        identifier=self.receipt();plan=self.j.plan(identifier)
        with patch.object(r,'boot',return_value='newboot'):
            with self.assertRaisesRegex(ValueError,'Boot changed'):self.j.apply(identifier,plan['confirmation'],'Review')
        with self.assertRaisesRegex(ValueError,'Receipt changed'):self.j.apply(identifier,plan['confirmation'],'Review')
    def test_partial_undo_is_not_retried(self):
        identifier=self.receipt();plan=self.j.plan(identifier)
        with patch('agent.run',side_effect=RuntimeError('interrupted')):
            with self.assertRaises(RuntimeError):self.j.apply(identifier,plan['confirmation'],'Review')
        self.assertEqual(self.j.read(identifier)['state'],'undo_uncertain')
        with self.assertRaisesRegex(ValueError,'manual review'):self.j.plan(identifier)
    def test_no_reason_no_mutation(self):
        identifier=self.receipt();plan=self.j.plan(identifier)
        with self.assertRaises(ValueError):self.j.apply(identifier,plan['confirmation'],' ')
        self.assertEqual(self.j.read(identifier)['state'],'contained')
    def test_irreversible_and_failed_actions_have_no_undo(self):
        self.executor.execute.side_effect=None;self.executor.execute.return_value={'verified':True}
        identifier=self.j.record(self.executor,{'action':'terminate_session'})['undo_receipt']
        with self.assertRaises(ValueError):self.j.plan(identifier)
        self.executor.execute.side_effect=RuntimeError('failed')
        with self.assertRaises(RuntimeError):self.receipt()
        self.assertTrue(any(x['state']=='forward_uncertain' for x in self.j.entries()))
    def test_receipts_are_private_and_reject_path_traversal(self):
        identifier=self.receipt()
        self.assertEqual(self.j.path(identifier).stat().st_mode&0o777,0o600)
        with self.assertRaises(ValueError):self.j.read('../incidents')
    def test_account_database_changes_refuse_restoration(self):
        identifier='a'*32
        self.j.save({'id':identifier,'action':'quarantine_account','target':'lab_test','state':'contained','eligible':True,'boot':'boot','after':{'uid':1001,'generation':1}})
        with patch.object(r,'account',return_value={'uid':1001,'generation':2}):
            with self.assertRaisesRegex(ValueError,'database changed'):self.j.plan(identifier)

    def test_later_account_claim_blocks_older_undo(self):
        row={'id':'a'*32,'action':'quarantine_account','target':'lab_test','state':'contained','eligible':True,'boot':'boot','after':{'uid':1001}}
        self.j.save(row);self.j.save(dict(row,id='b'*32,eligible=False))
        with patch.object(r,'account',return_value={'uid':1001}):
            with self.assertRaisesRegex(ValueError,'Another containment'):self.j.plan('a'*32)


    def test_account_plan_exposes_exact_restore_values_without_shadow_fingerprints(self):
        identifier='c'*32
        before={'uid':1001,'shell':'/bin/bash','expiry':'','locked':False,'shadow_hash':'private-fingerprint'}
        self.j.save({'id':identifier,'action':'quarantine_account','target':'lab_test','state':'contained','eligible':True,'boot':'boot','before':before,'after':{'uid':1001}})
        with patch.object(r,'account',return_value={'uid':1001}):plan=self.j.plan(identifier)
        self.assertEqual(plan['restore'],{'uid':1001,'shell':'/bin/bash','expiry':'','locked':False})
        self.assertNotIn('private-fingerprint',json.dumps(plan))


    def test_mapped_ip_receipt_matches_executor_canonical_target(self):
        result=self.j.record(self.executor,{'action':'block_ip','ip':'::ffff:198.51.100.44'})
        self.assertEqual(self.j.read(result['undo_receipt'])['target'],'198.51.100.44')


class FirewallFormat(unittest.TestCase):
    def test_nft_list_set_json_distinguishes_ownership_and_absence(self):
        ip='192.0.2.244'
        data={'nftables':[{'set':{'family':'inet','name':'blocked4','table':'defense_lab','type':'ipv4_addr','flags':['timeout'],'elem':[{'elem':{'val':ip,'timeout':60,'expires':59,'comment':'aegis-test'}}]}}]}
        with patch('agent.run',return_value=json.dumps(data)):
            self.assertEqual(r.ip_state(ip),{'comment':'aegis-test'})
            self.assertIsNone(r.ip_state('192.0.2.245'))
        data['nftables'][0]['set']['elem']=[ip]
        with patch('agent.run',return_value=json.dumps(data)):
            self.assertEqual(r.ip_state(ip),{'comment':None})
        data['nftables'][0]['set']['flags'].append('interval')
        with patch('agent.run',return_value=json.dumps(data)):
            with self.assertRaises(ValueError):r.ip_state(ip)
