"""Remove only accounts created by the isolated live-test fixtures."""
import os,pwd,re,subprocess,time


def remove_test_user(name):
    if not re.fullmatch(r'lab_(?:tel_\d{9}|up_\d{8})',name):
        raise ValueError('Not an AEGIS test account')
    home='/home/'+name
    try:account=pwd.getpwnam(name)
    except KeyError:
        if os.path.lexists(home):raise RuntimeError('Test account home remains: '+home)
        return
    uid=account.pw_uid
    if uid<1000 or account.pw_dir!=home:raise ValueError('Unexpected test account identity')
    for _ in range(20):
        try:account=pwd.getpwnam(name)
        except KeyError:break
        if account.pw_uid!=uid or account.pw_dir!=home:raise ValueError('Test account identity changed')
        subprocess.run(['pkill','-KILL','-u',str(uid)],capture_output=True,timeout=20)
        result=subprocess.run(['userdel','-r',name],capture_output=True,text=True,timeout=20)
        try:pwd.getpwnam(name)
        except KeyError:break
        time.sleep(.5)
    else:raise RuntimeError('Could not remove test account '+name+': '+result.stderr.strip())
    if os.path.lexists(home):raise RuntimeError('Test account home remains: '+home)
