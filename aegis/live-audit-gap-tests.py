#!/usr/bin/env python3
"""Isolated VM: audit-gap review and continuity using a disposable database."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import agent
import audit_spool
import console
import maintenance
import monitoring
import release_check


def check(name,condition):
    print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)


def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':
        raise SystemExit('Run only as root on the isolated defense-lab-01 VM')
    with tempfile.TemporaryDirectory(prefix='aegis-gap-') as directory:
        root=pathlib.Path(directory);(root/'ai').mkdir()
        c=dict(agent.DEFAULTS,data_dir=str(root),audit_spool_dir=str(root/'audit'),
               ai_results_dir=str(root/'ai'),application_log=str(root/'app'),application_enabled=False)
        store=agent.Store(c);spool=audit_spool.Spool(c)
        try:
            engine=agent.CorrelatedEngine(c,store,None);now=time.time()
            (spool.path.parent/'producer.json').write_text(json.dumps({'boot_id':engine.boot_id,'pid':123,'start_ticks':12}))
            journals={name:{'connected':True,'pid':124,'start_ticks':12} for name in ('ssh','journal_context')}
            def sources():
                with patch.object(monitoring,'process_state',return_value='running'),patch.object(monitoring,'service_active',return_value=True):
                    return monitoring.source_states(engine,spool,journals,{},time.time(),{'enabled':'1','lost':'0'})
            initial=sources()
            store.state('heartbeat',{'time':now,'pid':123,'boot_id':engine.boot_id})
            store.state('sensor_health',{'time':now,'audit':{'enabled':'1','lost':'0'},
                                       'audit_spool':{'dropped':0,'rows':0},'sources':initial})
            baseline=release_check.sample(store.db,now)
            check('initial_continuity_is_healthy',release_check.continuous(baseline,None))
            def line(serial):
                return f'type=SYSCALL msg=audit({time.time()}:{serial}): success=yes pid=999999 ppid=999998 uid=0 auid=1000 ses=4 exe="/usr/bin/true" key="lab_root_exec" msg="untrusted_fixture"'
            original=engine.account
            def reject(line):
                if ':100)' in line or ':102)' in line:raise ValueError('untrusted_fixture')
                return original(line)
            spool.append(line(100),engine.boot_id);spool.append(line(101),engine.boot_id)
            with patch.object(engine,'account',side_effect=reject):audit_spool.consume(engine,spool)
            check('bad_record_raises_gap_and_next_record_is_processed',sources()[0]['status']=='GAP' and store.db.execute('SELECT count(*) FROM correlation_events').fetchone()[0]==1)
            check('stale_healthy_snapshot_cannot_hide_new_gap',not release_check.continuous(release_check.sample(store.db,time.time()),None))
            cmd=[sys.executable,str(pathlib.Path(maintenance.__file__)),'--database',str(store.path)]
            def cli(*args):return subprocess.run(cmd+list(args),capture_output=True,text=True,timeout=15)
            check('stale_count_is_refused',cli('--ack-audit-parse','2','--reason','Wrong count').returncode!=0)
            check('operator_can_review_current_gap',cli('--ack-audit-parse','1','--reason','Investigated first gap').returncode==0)
            first=sources()[0]
            check('source_recovers_but_shows_previous_loss',first['status'] in ('LIVE','QUIET') and first['audit_parse_errors']==1 and first['audit_parse_reviewed']==1)
            view='\n'.join(console.source_lines({'sensor_health':{'time':time.time(),'sources':sources()}},100,time.time()))
            check('terminal_explains_lost_records', 'Historical parse gaps: 1' in view and 'Lost records are not recovered' in view)
            check('gap_between_samples_breaks_continuity',not release_check.continuous(release_check.sample(store.db,time.time()),baseline))
            engine=agent.CorrelatedEngine(c,store,None)
            check('review_survives_collector_restart',sources()[0]['audit_parse_reviewed']==1)
            spool.append(line(102),engine.boot_id)
            with patch.object(engine,'account',side_effect=reject):audit_spool.consume(engine,spool)
            check('new_error_reopens_gap',sources()[0]['status']=='GAP' and sources()[0]['audit_parse_errors']==2)
            check('previous_count_cannot_acknowledge_new_gap',cli('--ack-audit-parse','1','--reason','Stale').returncode!=0)
            check('new_gap_can_be_reviewed',cli('--ack-audit-parse','2','--reason','Investigated second gap').returncode==0)
            history=json.loads(cli('--audit-gap-history').stdout)
            check('history_is_durable_and_excludes_raw_log_text',[item['count'] for item in history]==[2,1] and 'untrusted_fixture' not in json.dumps(history))
            spool.row_limit=0;spool.append('overflow',engine.boot_id)
            check('other_audit_loss_still_reports_gap',sources()[0]['status']=='GAP')
        finally:spool.db.close();store.db.close()
    print('AUDIT_GAP_VM_TESTS_PASSED',flush=True)


if __name__=='__main__':main()
