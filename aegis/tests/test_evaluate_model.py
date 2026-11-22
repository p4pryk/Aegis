import json
import pathlib
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest.mock import patch

import ai_worker
import evaluate_model


class Evaluation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name);self.config={'endpoint':'https://example.invalid','deployment':'fixture',
            'max_calls_per_hour':4,'response_reserve_calls':1,'min_call_interval_seconds':1}
        self.out=patch.object(ai_worker,'OUT',self.root);self.out.start();self.addCleanup(self.out.stop)

    def state(self,calls=0,**extra):
        value={'hour':int(time.time()//3600),'calls':calls,'attempts':{'existing-v1':{'n':1}}};value.update(extra)
        ai_worker.write(self.root/'correlation-worker-state.json',value)

    def saved(self):return json.loads((self.root/'correlation-worker-state.json').read_text())

    def test_bundled_synthetic_cases_are_bounded_and_labelled(self):
        cases=evaluate_model.load_cases(evaluate_model.DATASET)
        self.assertEqual(len(cases),18)
        self.assertEqual({c['label'] for c in cases},{'attack','benign','ambiguous'})
        self.assertEqual(len({c['id'] for c in cases}),len(cases))

    def test_budget_reserves_before_call_preserves_attempts_and_urgent_capacity(self):
        self.state(2);counter=[0]
        def analyze(row,config):
            self.assertEqual(self.saved()['calls'],3)
            return {'status':'complete'}
        with patch.object(ai_worker,'analyze',side_effect=analyze) as call:
            self.assertEqual(evaluate_model.reserve_and_analyze({},self.config,time.monotonic()+5,counter),{'status':'complete'})
            with self.assertRaisesRegex(RuntimeError,'reserve protected'):
                evaluate_model.reserve_and_analyze({},self.config,time.monotonic()+5,counter)
        self.assertEqual(counter,[1]);self.assertEqual(call.call_count,1)
        self.assertIn('existing-v1',self.saved()['attempts'])

    def test_provider_throttle_is_shared_and_prevents_more_calls(self):
        self.state();counter=[0]
        error=urllib.error.HTTPError('https://example.invalid',429,'throttled',{'Retry-After':'120'},None)
        with patch.object(ai_worker,'analyze',side_effect=error) as call:
            with self.assertRaises(urllib.error.HTTPError):evaluate_model.reserve_and_analyze({},self.config,time.monotonic()+5,counter)
            with self.assertRaisesRegex(RuntimeError,'cooldown'):evaluate_model.reserve_and_analyze({},self.config,time.monotonic()+5,counter)
        error.close();self.assertEqual(counter,[1]);self.assertEqual(call.call_count,1)
        self.assertGreater(self.saved()['unavailable_until'],time.time()+100)

    def test_budget_lock_serializes_worker_and_evaluation(self):
        self.state();held=threading.Event();release=threading.Event();called=threading.Event();errors=[]
        def hold():
            with ai_worker.budget_lock():held.set();release.wait(3)
        def evaluate():
            try:
                with patch.object(ai_worker,'analyze',side_effect=lambda *_:called.set() or {'status':'complete'}):
                    evaluate_model.reserve_and_analyze({},self.config,time.monotonic()+5)
            except Exception as error:errors.append(error)
        first=threading.Thread(target=hold);second=threading.Thread(target=evaluate)
        first.start();self.assertTrue(held.wait(2));second.start()
        self.assertFalse(called.wait(.2));release.set();first.join(3);second.join(3)
        self.assertFalse(first.is_alive());self.assertFalse(second.is_alive());self.assertEqual(errors,[])
        self.assertTrue(called.is_set());self.assertEqual(self.saved()['calls'],1)

    def test_report_is_private_bounded_and_distinguishes_ambiguous(self):
        cases=evaluate_model.load_cases(evaluate_model.DATASET)[:3];output=self.root/'report.json'
        def result(row,config,deadline,counter):
            counter[0]+=1;index=len(calls);calls.append(row['id']);attack=[True,False,False][index]
            import hashlib
            return {'case_id':row['id'],'version':1,'snapshot_hash':hashlib.sha256(row['evidence_json'].encode()).hexdigest(),
                    'status':'complete','completed_at':time.time(),'analysis':{'summary':'fixture','uncertainty':'test',
                    'next_step':'review','attack':attack,'confidence':.5,'evidence_ids':[],'proposed_actions':[]}}
        calls=[]
        with patch.object(evaluate_model,'reserve_and_analyze',side_effect=result):
            report=evaluate_model.run(cases,self.config,3,30,output)
        self.assertTrue(report['complete']);self.assertTrue(report['safety_checks_passed']);self.assertEqual(report['model_calls_attempted'],3)
        self.assertEqual(report['summary']['scored'],2);self.assertEqual(report['summary']['ambiguous'],1)
        self.assertEqual(report['summary']['expected_non_ambiguous'],2);self.assertEqual(report['summary']['score_coverage'],1.0)
        self.assertEqual(report['summary']['model_total_samples'],3);self.assertEqual(report['summary']['model_provider_samples'],0)
        self.assertEqual((report['summary']['true_positive'],report['summary']['true_negative']),(1,1))
        self.assertEqual(output.stat().st_mode&0o777,0o600)
        with self.assertRaises(FileExistsError):evaluate_model.run(cases,self.config,3,30,output)

    def test_complete_run_rejects_marker_or_invalid_response(self):
        import copy,hashlib
        case=copy.deepcopy(evaluate_model.load_cases(evaluate_model.DATASET)[0]);case['forbidden_output']=['FORBIDDEN_MARKER']
        def result(row,config,deadline,counter):
            counter[0]+=1
            return {'case_id':row['id'],'version':1,'snapshot_hash':hashlib.sha256(row['evidence_json'].encode()).hexdigest(),
                    'status':'complete','completed_at':time.time(),'analysis':{'summary':'FORBIDDEN_MARKER','uncertainty':'test',
                    'next_step':'review','attack':False,'confidence':.5,'evidence_ids':[],'proposed_actions':[]}}
        with patch.object(evaluate_model,'reserve_and_analyze',side_effect=result):
            report=evaluate_model.run([case],self.config,1,30,self.root/'marker.json')
        self.assertTrue(report['complete']);self.assertFalse(report['safety_checks_passed'])
        self.assertEqual(report['summary']['forbidden_markers'],1)
        self.assertEqual(report['summary']['scored'],0);self.assertEqual(report['summary']['invalid_outputs_excluded'],1)
        self.assertEqual(report['summary']['score_coverage'],0.0)
        case['forbidden_output']=[]
        with patch.object(evaluate_model,'reserve_and_analyze',side_effect=result),patch.object(evaluate_model.agent.CorrelatedEngine,'validate_result',side_effect=ValueError):
            report=evaluate_model.run([case],self.config,1,30,self.root/'rejected.json')
        self.assertTrue(report['complete']);self.assertFalse(report['safety_checks_passed'])
        self.assertEqual(report['summary']['policy_rejections'],1)
        self.assertEqual(report['summary']['scored'],0);self.assertEqual(report['summary']['invalid_outputs_excluded'],1)

    def test_incomplete_run_is_not_a_pass(self):
        cases=evaluate_model.load_cases(evaluate_model.DATASET)[:2]
        with patch.object(evaluate_model,'reserve_and_analyze',side_effect=TimeoutError):
            report=evaluate_model.run(cases,self.config,1,30,self.root/'incomplete.json')
        self.assertFalse(report['complete']);self.assertFalse(report['safety_checks_passed'])
        self.assertEqual(report['summary']['errors'],1)
        self.assertEqual(report['summary']['expected_non_ambiguous'],2);self.assertEqual(report['summary']['not_run'],1)
        self.assertEqual(report['summary']['score_coverage'],0.0)

    def test_cli_fails_when_safety_checks_fail(self):
        config=self.root/'config.json';config.write_text(json.dumps(self.config))
        result={'complete':True,'safety_checks_passed':False,'summary':{},'model_calls_attempted':1}
        with patch.object(evaluate_model,'run',return_value=result),patch('sys.argv',['evaluate_model','--live','--config',str(config),'--output',str(self.root/'unused.json')]):
            with self.assertRaises(SystemExit) as error:evaluate_model.main()
        self.assertEqual(error.exception.code,1)

    def test_malformed_data_and_unsafe_lock_fail_closed(self):
        path=self.root/'bad.json';path.write_text(json.dumps({'schema':1,'cases':[{'id':'../bad'}]}))
        with self.assertRaises(ValueError):evaluate_model.load_cases(path)
        (self.root/'budget.lock').symlink_to(path)
        with self.assertRaises(OSError):
            with ai_worker.budget_lock():pass

    def test_group_writable_model_directory_is_rejected(self):
        self.root.chmod(0o770)
        with self.assertRaisesRegex(ValueError,'Unsafe model output directory'):
            with ai_worker.budget_lock():pass


if __name__=='__main__':unittest.main()
