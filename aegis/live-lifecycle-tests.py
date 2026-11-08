#!/usr/bin/env python3
"""Destructive-to-installation acceptance; only the designated isolated Azure VM.
Restores the demo configuration and current source even if an assertion fails.
This exercises a fresh agent profile, not a freshly provisioned operating system.
"""
import hashlib
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import tempfile
import time

import lifecycle

SOURCE=pathlib.Path(__file__).resolve().parent
CONFIG=pathlib.Path('/etc/defense-agent')
DATABASE='/var/lib/defense-agent/incidents.db'

def check(name, condition):
    print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)

def install(demo):
    with open('/tmp/aegis-lifecycle-install.log','w') as log:
        result=subprocess.run(['bash',str(SOURCE/'install.sh')]+(['--demo'] if demo else []),stdout=log,stderr=subprocess.STDOUT,timeout=240)
    if result.returncode:raise RuntimeError('Installer failed; inspect /tmp/aegis-lifecycle-install.log')
    time.sleep(11)

def latest():return max((p for p in lifecycle.ROOT.iterdir() if p.name.isdigit()),key=lambda p:int(p.name))

def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('This acceptance suite is restricted to the isolated defense-lab-01 host (Azure VM vm-defense-lab-01)')
    original={p.name:(p.read_bytes(),p.stat().st_mode&0o777) for p in CONFIG.glob('*.json')}
    if not json.loads(original['config.json'][0]).get('lab_response_enabled'):raise SystemExit('Explicit demo profile required')
    canary='release-'+str(time.time_ns())
    def retained():
        with sqlite3.connect(DATABASE) as db:
            row=db.execute("SELECT value FROM state WHERE key='release_test_canary'").fetchone()
            return row and row[0]==json.dumps(canary)
    with sqlite3.connect(DATABASE) as db:db.execute("INSERT OR REPLACE INTO state VALUES ('release_test_canary',?)",(json.dumps(canary),))
    try:
        backup=latest();manifest=lifecycle.load(backup)
        entry=next(e for e in manifest['files'] if e['path']=='/opt/defense-agent')
        expected=hashlib.sha256((backup/entry['backup']/'agent.py').read_bytes()).hexdigest()
        lifecycle.restore(backup)
        check('previous_release_code_restored',hashlib.sha256(pathlib.Path('/opt/defense-agent/agent.py').read_bytes()).hexdigest()==expected)
        check('release_rollback_preserves_incidents',retained())
        install(False)
        check('ordinary_upgrade_removes_existing_demo_code',not pathlib.Path('/opt/defense-agent/vulnerable_app.py').exists())
        install(True)
        check('update_recovers_current_code',pathlib.Path('/opt/defense-agent/agent.py').read_bytes()==(SOURCE/'agent.py').read_bytes())
        lifecycle.uninstall(latest())
        check('uninstall_removes_code_but_preserves_config_and_evidence',not pathlib.Path('/opt/defense-agent').exists() and (CONFIG/'config.json').exists() and retained())
        for name in ('config.json','ai.json'):(CONFIG/name).unlink(missing_ok=True)
        install(False)
        config=json.loads((CONFIG/'config.json').read_text())
        check('fresh_profile_defaults_to_observe',config['response_mode']=='observe' and not config['lab_response_enabled'])
        check('ordinary_profile_excludes_demo',not pathlib.Path('/opt/defense-agent/vulnerable_app.py').exists())
        check('collection_runs_without_model_configuration',subprocess.run(['systemctl','is-active','--quiet','defense-agent']).returncode==0 and not (CONFIG/'ai.json').exists())
        check('fresh_profile_preserves_existing_incidents',retained())
    finally:
        for name,(data,mode) in original.items():
            path=CONFIG/name;path.write_bytes(data);path.chmod(mode)
        install(True)
        with sqlite3.connect(DATABASE) as db:db.execute("DELETE FROM state WHERE key='release_test_canary'")
        print('DEMO_CONFIGURATION_RESTORED',flush=True)
    print('LIFECYCLE_ACCEPTANCE_COMPLETE')

if __name__=='__main__':main()
