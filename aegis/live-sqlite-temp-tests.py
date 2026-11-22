#!/usr/bin/env python3
"""Isolated VM only: reproduce SQLite temp-file failure without using agent data."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile

PROBE = '''
import json, os, sqlite3
result = {}
try:
    db = sqlite3.connect(os.environ['AEGIS_PROBE_DB'])
    db.execute('PRAGMA temp_store=FILE')
    db.execute('PRAGMA cache_size=20')
    db.execute('CREATE TEMP TABLE scratch (value BLOB)')
    with db:
        for _ in range(6000):
            db.execute('INSERT INTO scratch VALUES (randomblob(4096))')
    result.update(success=True, rows=db.execute('SELECT count(*) FROM scratch').fetchone()[0])
    db.close()
except sqlite3.Error as exc:
    result.update(success=False, sqlite_errorname=getattr(exc, 'sqlite_errorname', None),
                  sqlite_errorcode=getattr(exc, 'sqlite_errorcode', None))
print(json.dumps(result), flush=True)
'''


def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':
        raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    with tempfile.TemporaryDirectory(prefix='aegis-sqlite-probe-',dir='/var/lib') as root:
        results={}
        for mode in ('no','yes'):
            command=['systemd-run','--quiet','--wait','--pipe',
                     '--property=ProtectSystem=strict','--property=ProtectHome=yes',
                     '--property=PrivateTmp='+mode,'--property=ReadWritePaths='+root,
                     '--property=WorkingDirectory=/',
                     '--setenv=AEGIS_PROBE_DB='+str(pathlib.Path(root)/(mode+'.db')),
                     sys.executable,'-c',PROBE]
            result=subprocess.run(command,text=True,capture_output=True,timeout=120,check=True)
            results[mode]=json.loads(result.stdout)
            print(json.dumps({'private_tmp':mode,**results[mode]}),flush=True)
        if results['no'].get('sqlite_errorname')!='SQLITE_IOERR_GETTEMPPATH':
            raise RuntimeError('Baseline did not reproduce the expected SQLite temp-path failure')
        if results['yes'].get('success') is not True or results['yes'].get('rows')!=6000:
            raise RuntimeError('SQLite did not complete with a private temporary directory')
    print('SQLITE_TEMP_REGRESSION_PASSED',flush=True)


if __name__=='__main__':main()
