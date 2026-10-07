import json
import pathlib
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import agent
import response
import test_correlated as fixtures
import test_sessions as sessions


class PowerLoss(BaseException):
    pass


class ResponseRecovery(unittest.TestCase):
    setUp = fixtures.Correlation.setUp
    tearDown = fixtures.Correlation.tearDown
    build = sessions.SSHSessions.build
    names = sessions.SSHSessions.names
    apply = sessions.SSHSessions.apply
    proposal = fixtures.Correlation.proposal
    status = fixtures.Correlation.status

    def restart(self, execute):
        self.store.db.close()
        self.store = agent.Store(self.c)
        self.e = agent.CorrelatedEngine(self.c, self.store, execute)

    def test_restart_skips_verified_step_and_resumes_unknown_step(self):
        row = self.build()
        def interrupted(action):
            if action['action'] == 'terminate_session':
                raise PowerLoss()
            return {'verified': True}
        self.e.execute = interrupted
        with self.assertRaises(PowerLoss):
            self.apply(row, self.proposal(row))
        saved = json.loads(self.store.db.execute('SELECT result_json FROM cases WHERE id=?', (row[0],)).fetchone()[0])
        self.assertEqual([r['status'] for r in saved], ['executed', 'running', 'pending'])
        calls = []
        self.restart(lambda action: calls.append(action) or {'verified': True})
        self.e.tick()
        self.assertEqual(self.status(row), 'defended')
        self.assertEqual([a['action'] for a in calls], ['terminate_session', 'block_ip'])
        attempts = self.store.db.execute('SELECT attempt,completed_at FROM response_attempts WHERE case_id=? AND position=1 ORDER BY attempt', (row[0],)).fetchall()
        self.assertIsNone(attempts[0][1])
        self.assertIsNotNone(attempts[1][1])
        self.assertEqual(len(attempts), 2)

    def test_failure_keeps_history_and_does_not_repeat_successful_steps(self):
        row = self.build()
        calls = []
        def execute(action):
            calls.append(action['action'])
            if action['action'] == 'quarantine_account':
                raise TimeoutError('reply lost')
            return {'verified': True}
        self.e.execute = execute
        self.apply(row, self.proposal(row))
        self.e.tick(time.time()+6)
        self.e.tick(time.time()+17)
        self.assertEqual(self.status(row), 'defense_error')
        self.assertEqual(calls.count('quarantine_account'), 3)
        self.assertEqual(calls.count('terminate_session'), 1)
        self.assertNotIn('block_ip', calls)
        before = self.store.db.execute('SELECT result_json,kind,subject FROM cases WHERE id=?', (row[0],)).fetchone()
        self.e.create_or_append(before[1], before[2], self.e.normalize('service_event', 'context', {}, 'later', time.time()))
        self.assertEqual(self.store.db.execute('SELECT result_json FROM cases WHERE id=?', (row[0],)).fetchone()[0], before[0])
        self.assertEqual(self.store.db.execute('SELECT result_json FROM case_versions WHERE case_id=?', (row[0],)).fetchone()[0], before[0])

    def test_uncommitted_plan_is_not_recovered_as_authorized(self):
        row = self.build()
        with patch.object(self.e, 'status', side_effect=PowerLoss):
            with self.assertRaises(PowerLoss):
                self.apply(row, self.proposal(row))
        self.restart(lambda _: self.fail('uncommitted plan executed'))
        self.assertEqual(self.status(row), 'awaiting_analysis')
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM response_runs').fetchone()[0], 0)

    def interrupted(self):
        row = self.build()
        self.e.execute = Mock(side_effect=PowerLoss)
        with self.assertRaises(PowerLoss):
            self.apply(row, self.proposal(row))
        self.restart(lambda _: self.fail('invalidated recovery executed'))
        return row

    def test_policy_change_stops_recovery(self):
        row = self.interrupted()
        self.c['protected_users'] = [*self.c['protected_users'], 'lab_added']
        self.e.tick()
        self.assertEqual(self.status(row), 'defense_error')

    def test_boot_change_stops_recovery(self):
        row = self.interrupted()
        self.e.boot_id = 'another-boot'
        self.e.tick()
        self.assertEqual(self.status(row), 'defense_error')

    def test_expired_recovery_requires_review(self):
        row = self.interrupted()
        self.e.tick(time.time()+121)
        self.assertEqual(self.status(row), 'defense_error')

    def test_legacy_recognized_case_gets_explicit_error(self):
        row = self.build()
        self.e.status(row[0], 'recognized')
        self.e.tick()
        self.assertEqual(self.status(row), 'defense_error')
        self.assertFalse(self.actions)

    def test_changed_account_uid_is_rejected_by_executor(self):
        with patch.object(agent.pwd, 'getpwnam', return_value=Mock(pw_uid=2000)), patch.object(agent, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                agent.Executor(self.c).execute({'action': 'quarantine_account', 'user': 'lab_added', 'expected_uid': 1003})
            run.assert_not_called()

    def test_completed_assessment_is_archived_before_new_evidence(self):
        event = self.e.normalize('ssh_failure', '198.51.100.8', {}, 'failure-one', time.time())
        identifier = self.e.create_or_append('ssh_threshold', event['subject'], event)
        self.store.db.execute("UPDATE cases SET analysis_json=?,status='observing' WHERE id=?", (json.dumps({'summary': 'Original assessment'}), identifier))
        self.store.db.commit()
        self.e.create_or_append('ssh_threshold', event['subject'], dict(event, event_id='failure-two'))
        history = self.store.db.execute('SELECT analysis_json FROM case_versions WHERE case_id=?', (identifier,)).fetchone()
        self.assertEqual(json.loads(history[0])['summary'], 'Original assessment')


if __name__ == '__main__':
    unittest.main()
