import json
import pathlib
import queue
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import agent
import journal_sources
import journal_stream


class JournalRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = dict(agent.DEFAULTS, data_dir=self.tmp.name)
        self.store = agent.Store(self.config)
        self.addCleanup(self.store.db.close)
        self.engine = agent.CorrelatedEngine(self.config, self.store, lambda _: self.fail('unexpected response'))
        self.record = {'__CURSOR': 'cursor-1', '_BOOT_ID': self.engine.boot_id,
                       '__REALTIME_TIMESTAMP': str(int(time.time()*1e6)),
                       '_COMM': 'sshd', '_UID': '0',
                       'MESSAGE': 'Failed password for lab_actor from 198.51.100.9 port 2222'}

    def test_real_journald_boot_format_matches_kernel_identity(self):
        self.engine.boot_id = '12345678-1234-1234-1234-123456789abc'
        raw = dict(self.record, _BOOT_ID=self.engine.boot_id.replace('-', ''))
        self.engine.journal_ssh(raw)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0], 1)
        raw.update(_COMM='sudo', _AUDIT_SESSION='42', _AUDIT_LOGINUID='1000',
                   MESSAGE='lab_actor : USER=root ; COMMAND=/bin/true', __CURSOR='sudo-real-boot')
        self.engine.journal_context(raw)
        login = {'event_time': time.time()-1, 'details': {'boot_id': self.engine.boot_id, 'session': '42', 'auid': '1000'}}
        context = self.engine.session_context_events(login, time.time()+1)
        self.assertEqual(len(context), 1)
        self.assertEqual(context[0]['details']['boot_id'], self.engine.boot_id)

    def test_cursor_only_advances_after_consumer_commit(self):
        checkpoints = journal_stream.Checkpoints(self.store)
        events = queue.Queue()
        journal_stream.enqueue(events, 'ssh', self.record, {})
        self.assertIsNone(journal_stream.Checkpoints(self.store).cursor('ssh'))
        source, record = events.get_nowait()
        self.engine.journal_ssh(record)
        checkpoints.commit(self.store, {source: record})
        restored = journal_stream.Checkpoints(self.store)
        self.assertEqual(restored.cursor('ssh'), 'cursor-1')
        self.assertIn('--after-cursor=cursor-1', journal_stream.arguments('ssh', self.config, restored.cursor('ssh')))

    def test_replay_is_deduplicated(self):
        self.engine.journal_ssh(self.record)
        self.engine.journal_ssh(self.record)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0], 1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM observations').fetchone()[0], 1)

    def test_ssh_replay_supports_ten_minute_window(self):
        self.record['__REALTIME_TIMESTAMP'] = str(int((time.time()-300)*1e6))
        self.engine.journal_ssh(self.record)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0], 1)

    def test_old_journal_backlog_is_not_treated_as_a_new_incident(self):
        self.record['__REALTIME_TIMESTAMP'] = str(int((time.time()-601)*1e6))
        self.engine.journal_ssh(self.record)
        raw = dict(self.record, _COMM='sudo', MESSAGE='lab_actor : USER=root ; COMMAND=/bin/true')
        self.engine.journal_context(raw)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0], 0)

    def test_context_source_resumes_from_cursor_without_relative_lookback(self):
        args = journal_stream.arguments('journal_context', self.config, 'context-cursor')
        self.assertIn('--after-cursor=context-cursor', args)
        self.assertFalse(any(arg.startswith('--since=') for arg in args))

    def test_previous_boot_cannot_become_current_session_context(self):
        raw = dict(self.record, _BOOT_ID='old-boot', _COMM='sudo', _AUDIT_SESSION='42',
                   _AUDIT_LOGINUID='1000', MESSAGE='lab_actor : USER=root ; COMMAND=/usr/bin/useradd lab_new')
        event = journal_sources.parse(raw, self.engine.boot_id, self.config)
        self.assertEqual(event['details']['boot_id'], 'old-boot')
        self.engine.journal_context(raw)
        login = {'event_time': time.time(), 'details': {'boot_id': self.engine.boot_id, 'session': '42', 'auid': '1000'}}
        self.assertEqual(self.engine.session_context_events(login, time.time()+1), [])
        self.engine.journal_ssh(dict(self.record, _BOOT_ID='old-boot'))
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM cases').fetchone()[0], 0)

    def test_missing_boot_is_not_guessed(self):
        raw = dict(self.record, _COMM='sudo', MESSAGE='lab_actor : USER=root ; COMMAND=/bin/true')
        del raw['_BOOT_ID']
        self.assertIsNone(journal_sources.parse(raw, self.engine.boot_id, self.config))

    def test_full_queue_retries_same_record(self):
        events = Mock()
        events.put.side_effect = [queue.Full, None]
        health = {}
        journal_stream.enqueue(events, 'ssh', self.record, health)
        self.assertEqual(events.put.call_count, 2)
        self.assertEqual(events.put.call_args_list[0], events.put.call_args_list[1])
        self.assertEqual(health['backpressure_count'], 1)

    def test_invalid_cursor_falls_back_with_visible_gap(self):
        first = Mock(pid=999998,stdout=iter([]));first.wait.return_value = 1
        second = Mock(pid=999999,stdout=iter([json.dumps(self.record)]));second.wait.return_value = 0
        first.__enter__ = Mock(return_value=first);first.__exit__ = Mock(return_value=False)
        second.__enter__ = Mock(return_value=second);second.__exit__ = Mock(return_value=False)
        checkpoints = Mock();checkpoints.cursor.return_value = 'removed-cursor'
        health = {};events = queue.Queue()
        with patch.object(journal_stream.subprocess, 'Popen', side_effect=[first, second]) as popen, patch.object(journal_stream.time, 'sleep', side_effect=[None, InterruptedError]):
            with self.assertRaises(InterruptedError):
                journal_stream.reader(events, 'ssh', self.config, checkpoints, health)
        self.assertIn('--after-cursor=removed-cursor', popen.call_args_list[0].args[0])
        self.assertIn('--since=10 minutes ago', popen.call_args_list[1].args[0])
        self.assertIn('cursor_gap_at', health)
        self.assertEqual(events.get_nowait()[1], self.record)


if __name__ == '__main__':
    unittest.main()
