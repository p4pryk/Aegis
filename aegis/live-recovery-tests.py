#!/usr/bin/env python3
"""Root-only lab acceptance: real side effects, process crashes and journal replay.

The recovery harness enrolls an explicit fixture plan, not a model verdict.
Use live-session-tests.py and live-app-tests.py separately for detection coverage.
"""
import hashlib
import json
import os
import pathlib
import pwd
import select
import sqlite3
import subprocess
import tempfile
import time

import agent
import journal_stream
import persistence
import response


def check(name, condition):
    print(json.dumps({'test': name, 'passed': bool(condition)}), flush=True)
    if not condition:
        raise AssertionError(name)


def command(args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=10)


def next_record(process, marker):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if select.select([process.stdout], [], [], .2)[0]:
            line = process.stdout.readline()
            if not line:
                raise RuntimeError('journalctl exited before expected record')
            record = json.loads(line)
            if record.get('MESSAGE') == marker:
                return record
    raise TimeoutError('journal record not received')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run as root on the isolated training VM only')
    suffix = str(time.time_ns())[-10:]
    user = 'lab_recover_' + suffix
    path = pathlib.Path('/etc/cron.d/lab_aegis_r_' + suffix)
    content = b'*/5 * * * * root /usr/bin/true\n'
    digest = hashlib.sha256(content).hexdigest()
    backup = persistence.QUARANTINE / (path.name + '.' + digest)
    processes = []
    created_user = False
    try:
        command(['useradd', '-M', '-s', '/bin/bash', user]);created_user = True
        with path.open('xb') as f:
            f.write(content)
        path.chmod(0o644)
        with tempfile.TemporaryDirectory(prefix='aegis-recovery-') as directory:
            config = dict(agent.DEFAULTS, data_dir=directory)
            store = agent.Store(config)
            engine = agent.CorrelatedEngine(config, store, agent.Executor(config).execute)
            event = engine.normalize('account_created', user, {'account_uid': pwd.getpwnam(user).pw_uid}, 'recovery-fixture', time.time())
            identifier = engine.create_or_append('recovery_fixture', user, event)
            data = {'events': [event], 'allowed_actions': [
                {'action': 'quarantine_account', 'user': user},
                {'action': 'quarantine_persistence', 'path': str(path), 'sha256': digest}]}
            store.db.execute('UPDATE cases SET evidence_json=?,analysis_json=? WHERE id=?',
                             (json.dumps(data), json.dumps({'summary': 'Explicit authorized recovery test fixture'}), identifier))
            response.prepare(engine, identifier, data)
            engine.status(identifier, 'recognized')
            store.db.close()

            def crash_after(kind):
                pid = os.fork()
                if pid == 0:
                    try:
                        child_store = agent.Store(config)
                        executor = agent.Executor(config)
                        def execute(action):
                            result = executor.execute(action)
                            if action['action'] == kind:
                                os._exit(77)  # Side effect completed, result never committed.
                            return result
                        child = agent.CorrelatedEngine(config, child_store, execute)
                        response.advance(child, identifier)
                    except BaseException:
                        os._exit(2)
                    os._exit(3)
                _, status = os.waitpid(pid, 0)
                check('crash_after_' + kind, os.waitstatus_to_exitcode(status) == 77)

            crash_after('quarantine_account')
            check('account_effect_survives_lost_reply', pwd.getpwnam(user).pw_shell == '/usr/sbin/nologin')
            crash_after('quarantine_persistence')
            check('file_move_survives_lost_reply', not path.exists() and backup.exists())
            store = agent.Store(config)
            try:
                engine = agent.CorrelatedEngine(config, store, agent.Executor(config).execute)
                response.advance(engine, identifier)
                state, raw = store.db.execute('SELECT status,result_json FROM cases WHERE id=?', (identifier,)).fetchone()
                results = json.loads(raw)
                check('restart_reconciles_all_steps', state == 'defended' and all(r['result']['verified'] for r in results))
                check('moved_file_is_reconciled_without_recreating_it', results[1]['result'].get('already_quarantined') is True)
                check('verified_account_is_not_repeated_after_second_restart', store.db.execute('SELECT attempts FROM response_steps WHERE case_id=? AND position=0', (identifier,)).fetchone()[0] == 2)
                check('attempt_history_retained', store.db.execute('SELECT count(*) FROM response_attempts WHERE case_id=?', (identifier,)).fetchone()[0] == 4)
                check('completed_version_archived', store.db.execute('SELECT result_json FROM case_versions WHERE case_id=?', (identifier,)).fetchone()[0] == raw)

                journal_config = dict(config, journal_comms=[], journal_units=[], journal_identifiers=['aegis-recovery-' + suffix])
                checkpoints = journal_stream.Checkpoints(store)
                def start_reader():
                    process = subprocess.Popen(journal_stream.arguments('journal_context', journal_config, checkpoints.cursor('journal_context')), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    processes.append(process)
                    return process
                process = start_reader()
                tag = journal_config['journal_identifiers'][0]
                command(['logger', '-t', tag, 'before-restart-' + suffix])
                first = next_record(process, 'before-restart-' + suffix)
                checkpoints.commit(store, {'journal_context': first})
                process.terminate();process.wait(timeout=5)
                command(['logger', '-t', tag, 'during-downtime-' + suffix])
                checkpoints = journal_stream.Checkpoints(store)
                process = start_reader()
                second = next_record(process, 'during-downtime-' + suffix)
                check('journal_replays_record_written_during_downtime', second['__CURSOR'] != first['__CURSOR'] and second['_BOOT_ID'] == first['_BOOT_ID'])
                checkpoints.commit(store, {'journal_context': second})
                check('consumer_checkpoint_survives_restart', journal_stream.Checkpoints(store).cursor('journal_context') == second['__CURSOR'])
            finally:
                store.db.close()
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate();process.wait(timeout=5)
        if created_user:
            command(['userdel', user])
        path.unlink(missing_ok=True)
        backup.unlink(missing_ok=True)


if __name__ == '__main__':
    main()
