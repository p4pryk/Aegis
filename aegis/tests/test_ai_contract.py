import json,pathlib,sys,unittest
from unittest.mock import patch,MagicMock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import ai_worker as w

class ModelCatalog(unittest.TestCase):
 def run_analysis(self,ids):
  action={'action':'terminate_session','boot_id':'test-boot','session':42,'auid':1002,'user':'lab_actor'}
  evidence={'events':[{'event_id':'proof'}],'allowed_actions':[action]}
  output={'summary':'Opis sesji i zmiany.','uncertainty':'Brak dowodu kradzieży hasła.','next_step':'Ograniczyć sesję.','attack':True,'confidence':.9,'evidence_ids':['proof'],'proposed_action_ids':ids}
  response=MagicMock();response.__enter__.return_value.read.return_value=json.dumps({'choices':[{'message':{'content':json.dumps(output)}}]}).encode()
  row={'id':'case','kind':'ssh_session_account','version':1,'evidence_json':json.dumps(evidence)}
  with patch.object(w,'token',return_value='fake'),patch.object(w.urllib.request,'urlopen',return_value=response):
   return w.analyze(row,{'deployment':'test','endpoint':'https://example.invalid'})
 def test_model_selects_id_root_parameters_remain_exact(self):
  r=self.run_analysis(['a0']);a=r['analysis']['proposed_actions'][0]
  self.assertEqual(a,{'action':'terminate_session','boot_id':'test-boot','session':42,'auid':1002,'user':'lab_actor'})
  self.assertIs(type(a['session']),int)
 def test_unknown_action_id_rejected(self):
  with self.assertRaises(ValueError):self.run_analysis(['invented'])
 def test_duplicate_action_id_rejected(self):
  with self.assertRaises(ValueError):self.run_analysis(['a0','a0'])
 def test_approved_creation_description_uses_known_policy_without_model(self):
  evidence={'events':[{'event_id':'proof','kind':'account_created','subject':'lab_new'}],'allowed_actions':[],'policy':{'actor':'labadmin','actor_authorization':'approved'}}
  row={'id':'case','version':1,'evidence_json':json.dumps(evidence)}
  r=w.local_authorized_analysis(row);self.assertFalse(r['analysis']['attack']);self.assertEqual(r['model'],'local-authorization-policy')
  self.assertIn('labadmin',r['analysis']['summary'])
 def test_empty_action_selection_is_allowed(self):
  self.assertEqual(self.run_analysis([])['analysis']['proposed_actions'],[])
if __name__=='__main__':unittest.main()
