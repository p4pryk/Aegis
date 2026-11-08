#!/usr/bin/env python3
"""Exercise SSH spray detection only on the designated isolated Azure lab VM."""
import json
import os
import pathlib
import pwd
import socket
import sqlite3
import subprocess
import sys
import time

sys.path.insert(0,'/opt/defense-agent')
import console

NS='aegis-spray-test';HOST='10.252.81.1';IP='10.252.81.2';DEV='aegis-sp-host';PEER='aegis-sp-peer'

def run(*args,check=True,timeout=15):
    return subprocess.run(args,check=check,capture_output=True,text=True,timeout=timeout)

def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only on the isolated AEGIS test VM')
    suffix=str(time.time_ns())[-6:];users=['aegis_spray_'+suffix+'_'+str(n) for n in range(5)]
    for user in users:
        try:pwd.getpwnam(user)
        except KeyError:continue
        raise RuntimeError('Fixture account already exists')
    started=time.time()
    try:
        run('ip','netns','add',NS);run('ip','link','add',DEV,'type','veth','peer','name',PEER)
        run('ip','link','set',PEER,'netns',NS);run('ip','addr','add',HOST+'/30','dev',DEV);run('ip','link','set',DEV,'up')
        run('ip','netns','exec',NS,'ip','addr','add',IP+'/30','dev',PEER);run('ip','netns','exec',NS,'ip','link','set',PEER,'up');run('ip','netns','exec',NS,'ip','link','set','lo','up')
        run('nft','list','table','inet','defense_lab')
        for user in users:
            result=run('ip','netns','exec',NS,'ssh','-F','/dev/null','-o','BatchMode=yes','-o','PreferredAuthentications=none','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','GlobalKnownHostsFile=/dev/null','-o','ConnectTimeout=3',user+'@'+HOST,'true',check=False)
            if result.returncode==0:raise RuntimeError('Unexpected successful test login')
        deadline=time.monotonic()+90;case=None
        while time.monotonic()<deadline:
            with sqlite3.connect('/var/lib/defense-agent/incidents.db',timeout=10) as db:
                db.row_factory=sqlite3.Row
                rows=db.execute("SELECT * FROM cases WHERE kind='ssh_threshold' AND subject=? AND created_at>=? ORDER BY created_at DESC",(IP,started)).fetchall()
            for row in rows:
                evidence=json.loads(row['evidence_json'])
                if any(s.get('kind')=='possible_ssh_password_spray' for s in evidence.get('signals',[])):
                    case=dict(row);break
            if case:break
            time.sleep(.5)
        if not case:raise RuntimeError('Five-account SSH pattern was not detected')
        evidence=json.loads(case['evidence_json']);signal=next(s for s in evidence['signals'] if s['kind']=='possible_ssh_password_spray')
        assert signal['distinct_accounts']>=5 and not evidence['allowed_actions']
        blocked=run('nft','get','element','inet','defense_lab','blocked4','{',IP,'}',check=False)
        assert blocked.returncode!=0
        assert 'Possible SSH password spraying' in '\n'.join(console.case_lines({'cases':[case]},120))
        print(json.dumps({'test':'live_ssh_distinct_accounts_review_only','passed':True,'accounts':signal['distinct_accounts'],'ip_blocked':False}))
        print('SSH_SPRAY_LIVE_VERIFIED')
    finally:
        run('ip','netns','delete',NS,check=False);run('ip','link','delete',DEV,check=False)

if __name__=='__main__':main()
