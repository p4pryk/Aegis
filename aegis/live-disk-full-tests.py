#!/usr/bin/env python3
"""Isolated VM: real ENOSPC on tmpfs must leave a durable audit-loss marker."""
import errno
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time


SOURCE=pathlib.Path(__file__).resolve().parent


def wait(predicate,seconds=20):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.05)
    raise RuntimeError('Timed out waiting for the test producer')


def run_case(restart):
    with tempfile.TemporaryDirectory(prefix='aegis-full-test-',dir='/run') as outer:
        root=pathlib.Path(outer);mount=root/'spool';runtime=root/'runtime';mount.mkdir();runtime.mkdir(mode=0o700)
        mounted=False;producer=None
        config={'audit_spool_dir':str(mount),'runtime_dir':str(runtime)};marker=runtime/'audit-loss.pending'
        def start():
            code='import json,sys;sys.path.insert(0,sys.argv[1]);from audit_spool import forward;forward(json.loads(sys.argv[2]),sys.stdin.buffer)'
            return subprocess.Popen([sys.executable,'-u','-c',code,str(SOURCE),json.dumps(config)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def send(number):
            line=f'type=SYSCALL msg=audit({time.time():.3f}:{number}): success=yes pid=1 ppid=1 uid=0 auid=1000 ses=1 exe="/usr/bin/true" key="lab_root_exec"\n'
            producer.stdin.write(line.encode());producer.stdin.flush()
        try:
            subprocess.run(['mount','-t','tmpfs','-o','size=2m,nosuid,nodev,noexec','tmpfs',str(mount)],check=True,capture_output=True,timeout=10);mounted=True
            producer=start();wait(lambda:(mount/'producer.json').exists() or producer.poll() is not None)
            if producer.poll() is not None:raise RuntimeError('Fixture producer failed to start')
            filler=mount/'filler'
            with filler.open('wb',buffering=0) as out:
                while True:
                    try:out.write(b'X'*65536)
                    except OSError as error:
                        if error.errno!=errno.ENOSPC:raise
                        break
            send(1)
            ready,_,_=select.select([producer.stdout],[],[],10)
            if not ready or 'AEGIS AUDIT LOSS' not in producer.stdout.readline().decode(errors='replace'):
                raise RuntimeError('No loss warning received while the test filesystem was full')
            wait(marker.exists)
            if restart:
                producer.terminate();producer.wait(timeout=10)
            filler.unlink()
            if restart:producer=start()
            # No new record is sent: recovery must be retried while the pipe is idle.
            wait(lambda:not marker.exists())
            send(2);producer.stdin.close()
            if producer.wait(timeout=15):raise RuntimeError('Fixture producer failed after recovery')
            sys.path.insert(0,str(SOURCE));from audit_spool import Spool
            spool=Spool(config)
            try:health=spool.health()
            finally:spool.db.close()
            if not health.get('io_error_at') or health.get('io_error_pending') or health.get('accepted')!=1:
                raise AssertionError('Loss was not durably reported while the later record recovered')
            print(json.dumps({'test':'producer_restart_after_full_disk' if restart else 'idle_recovery_after_full_disk','passed':True,'accepted_after_recovery':health['accepted']}),flush=True)
        finally:
            if producer and producer.poll() is None:producer.terminate();producer.wait(timeout=10)
            if mounted:subprocess.run(['umount',str(mount)],check=True,capture_output=True,timeout=10)


if __name__=='__main__':
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    run_case(False);run_case(True)
    print('DISK_FULL_RECOVERY_PASSED')
