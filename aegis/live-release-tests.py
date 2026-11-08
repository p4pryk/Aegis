#!/usr/bin/env python3
"""Isolated VM release acceptance: real account effects and protected rollback.
The account action is an explicit executor fixture, not evidence of attack detection.
"""
import json
import os
import pwd
import subprocess
import tempfile
import time

import agent
import rollback

COUNT=0

def check(name, condition):
    global COUNT
    print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(name)
    COUNT+=1

def command(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=20)

def main():
    if os.geteuid()!=0:raise SystemExit('Use only the isolated test VM as root')
    user='aegischeck_'+str(time.time_ns())[-9:];created=False
    with tempfile.TemporaryDirectory(prefix='aegis-release-') as directory:
        try:
            command('useradd','-M','-s','/bin/bash',user);created=True
            config=dict(agent.DEFAULTS,data_dir=directory,response_users=[user])
            request={'action':'quarantine_account','user':user,'expected_uid':pwd.getpwnam(user).pw_uid}
            for mode in ('observe','review'):
                config['response_mode']=mode
                try:agent.Executor(config).execute(request)
                except ValueError:pass
                else:raise AssertionError('Non-enforce mode performed containment')
                check(mode+'_preserves_real_account',pwd.getpwnam(user).pw_shell=='/bin/bash')
            config['response_mode']='enforce';journal=rollback.Journal(config)
            result=journal.record(agent.Executor(config),request)
            check('explicit_non_lab_account_containment',result['verified'] and pwd.getpwnam(user).pw_shell=='/usr/sbin/nologin')
            command('usermod','-aG','sudo',user)
            try:journal.plan(result['undo_receipt'])
            except ValueError:pass
            else:raise AssertionError('Changed group membership accepted for rollback')
            check('rollback_refuses_changed_group_membership',True)
            command('gpasswd','-d',user,'sudo')
            plan=journal.plan(result['undo_receipt']);restored=journal.apply(result['undo_receipt'],plan['confirmation'],'Isolated release fixture cleanup')
            check('non_lab_account_rollback_verified',restored['verified'] and pwd.getpwnam(user).pw_shell=='/bin/bash')
            config['response_users']=[]
            try:agent.Executor(config).execute(request)
            except ValueError:pass
            else:raise AssertionError('Unscoped account modified')
            check('unscoped_account_preserved',pwd.getpwnam(user).pw_shell=='/bin/bash')
        finally:
            if created:command('userdel',user)
    print('RELEASE CHECKS PASSED: '+str(COUNT))

if __name__=='__main__':main()
