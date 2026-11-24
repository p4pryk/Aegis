#!/usr/bin/env python3
"""Root-only Linux fixture: isolated audit stream gaps and review commands."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

import audit_spool
import maintenance


def check(name,condition):
    print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)


def main():
    if os.geteuid()!=0 or not pathlib.Path('/proc/sys/kernel/random/boot_id').exists():
        raise SystemExit('Run as root on an isolated Linux VM')
    with tempfile.TemporaryDirectory(prefix='aegis-stream-review-') as directory:
        root=pathlib.Path(directory);config={'audit_spool_dir':str(root/'spool'),'runtime_dir':str(root/'run')}
        spool_path=root/'spool'/'inbox.db';source=pathlib.Path(maintenance.__file__).resolve().parent
        env=os.environ.copy();env['PYTHONPATH']=str(source)+os.pathsep+env.get('PYTHONPATH','')
        producer=[sys.executable,'-c','import audit_spool,json,sys;audit_spool.forward(json.loads(sys.argv[1]),sys.stdin)',json.dumps(config)]
        payload='type=SYSCALL msg=audit(1700000000.0:1): success=yes pid=1 key="lab_root_exec"'
        def gap():
            result=subprocess.run(producer,input=payload,text=True,capture_output=True,timeout=15,env=env)
            if result.returncode:raise RuntimeError('Fixture producer failed: '+result.stderr[:300])
        def state():
            spool=audit_spool.Spool(config)
            try:return spool.health()
            finally:spool.db.close()
        def review(identity,count):
            return subprocess.run([sys.executable,str(source/'maintenance.py'),'--spool-database',str(spool_path),'--ack-audit-stream',str(count),'--spool-identity',identity,'--reason','Controlled fixture review'],capture_output=True,text=True,timeout=15,env=env)
        gap();first=state();identity=first['identity']
        check('partial_record_sets_persistent_gap',first['stream_gaps']==1 and first['stream_reviewed']==0 and first['accepted']==0)
        check('wrong_inbox_identity_refused',review('f'*32,1).returncode!=0 and state()['stream_reviewed']==0)
        check('exact_review_recorded',review(identity,1).returncode==0 and state()['stream_reviewed']==1)
        history=maintenance.audit_stream_history(spool_path)
        check('review_history_persists',len(history)==1 and history[0]['count']==1 and history[0]['inbox_identity']==identity)
        gap();second=state();check('new_gap_reopens',second['stream_gaps']==2 and second['stream_reviewed']==1)
        check('stale_review_refused',review(identity,1).returncode!=0 and state()['stream_reviewed']==1)
        spool=audit_spool.Spool(config)
        try:audit_spool.mark_io_loss(spool.loss_marker)
        finally:spool.db.close()
        check('other_gap_survives_review',review(identity,2).returncode==0 and state()['io_error_pending'] is True)
    print('AUDIT_STREAM_REVIEW_VM_PASSED')


if __name__=='__main__':main()
