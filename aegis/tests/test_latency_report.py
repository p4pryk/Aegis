import json
import sqlite3
import unittest

import latency_report


class LatencyReport(unittest.TestCase):
    def test_missing_and_invalid_samples_do_not_skew_percentiles(self):
        db=sqlite3.connect(':memory:')
        db.execute('CREATE TABLE case_timings(collection_ms,model_queue_ms,model_ms,result_wait_ms,response_ms)')
        db.executemany('INSERT INTO case_timings VALUES (?,?,?,?,?)',[(10,1,None,3,None),(30,2,9,4,12),(20,3,-1,5,16)])
        db.execute('CREATE TABLE response_steps(status,result_json)')
        db.executemany('INSERT INTO response_steps VALUES (?,?)',[('executed',json.dumps({'reaction_ms':45})),('executed','bad'),('pending','{}')])
        report=latency_report.summarize(db)
        self.assertEqual(report['stages']['collection_ms']['p50'],20)
        self.assertEqual(report['stages']['collection_ms']['p95'],30)
        self.assertEqual(report['stages']['model_ms']['samples'],1)
        self.assertEqual(report['stages']['model_ms']['missing_or_invalid'],2)
        self.assertEqual(report['reaction_from_last_evidence_ms']['samples'],1)
        self.assertEqual(report['reaction_from_last_evidence_ms']['missing_or_invalid'],1)
        self.assertEqual(latency_report.summarize(db,1)['case_samples'],1)
        with self.assertRaises(ValueError):latency_report.summarize(db,10001)
