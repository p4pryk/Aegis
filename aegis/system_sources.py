"""Selected Linux system events. Text is evidence, never trusted process identity."""
import datetime, hashlib, ipaddress, os, pathlib, re, shutil, time

IDENTIFIERS=('login','sshd','sshd-session','sudo','su','su-l','passwd','chpasswd','useradd','userdel','usermod','groupadd','groupdel','groupmod','gpasswd','cron','CRON','crond','CROND','systemd','kernel')
PATHS={'auth':('/var/log/auth.log','/var/log/secure'),'system':('/var/log/syslog','/var/log/messages'),'kernel':('/var/log/kern.log',),'cron':('/var/log/cron',)}

def family(program):
    if program in ('kernel','audit'):return 'kernel'
    if program.lower() in ('cron','crond'):return 'cron'
    if program in IDENTIFIERS and program!='systemd':return 'auth'
    return 'system'

def discover(config):
    mode=config.get('system_log_mode','auto')
    if mode not in ('auto','journal','files'):raise ValueError('system_log_mode must be auto, journal or files')
    journal=bool(shutil.which('journalctl') and os.path.exists('/run/systemd/journal/socket'))
    selected=('journal' if journal else 'files') if mode=='auto' else mode
    overrides=config.get('system_log_paths',{})
    if not isinstance(overrides,dict) or set(overrides)-set(PATHS):raise ValueError('Invalid system_log_paths categories')
    paths={}
    for category,candidates in PATHS.items():
        if category in overrides:
            value=overrides[category]
            if not isinstance(value,str) or not pathlib.Path(value).is_absolute() or '..' in pathlib.Path(value).parts:raise ValueError('System log path must be absolute')
            paths[category]=value
        else:paths[category]=next((p for p in candidates if os.path.exists(p)),candidates[0])
    if len(set(paths.values()))!=len(paths):raise ValueError('System log paths must be distinct')
    return selected,paths,journal

def parse(program,message,stamp,event_id,source,boot_id=None,metadata=None):
    """Whitelist fields; never keep raw messages, arguments or credential material."""
    if not isinstance(message,str) or len(message)>8192 or not re.fullmatch(r'[A-Za-z0-9_.@/-]{1,64}',program):return None
    msg=message;details={'source':source,'program':program,'boot_id':boot_id,'transport':'journal' if boot_id else 'file','identity_verified':False}
    # Only journal-supplied audit fields, never PID/session text embedded in MESSAGE.
    if metadata and boot_id:
        for key,target in (('_AUDIT_SESSION','audit_session'),('_AUDIT_LOGINUID','auid')):
            value=str(metadata.get(key,''))
            if value.isdigit() and 0<=int(value)<4294967295:details[target]=value
    kind=description=None;review=False;subject=program
    if program in ('sshd','sshd-session'):
        auth=re.match(r'(Failed|Accepted) (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?([A-Za-z0-9_.@-]{1,64}) from ([0-9a-fA-F:.]+)\b',msg)
        invalid=re.match(r'Invalid user ([A-Za-z0-9_.@-]{1,64}) from ([0-9a-fA-F:.]+)\b',msg)
        if auth or invalid:
            user,ip=(auth[2],auth[3]) if auth else (invalid[1],invalid[2])
            try:details['ip']=str(ipaddress.ip_address(ip))
            except ValueError:return None
            details['user']=user;subject=user
            review=not auth or auth[1]=='Failed';kind='system_auth_failure' if review else 'system_auth_success'
            description='Authentication failure reported.' if review else 'Successful authentication reported; no kernel session identity established by this message.'
    if kind is None and program in IDENTIFIERS:
        session=re.search(r'session (opened|closed) for user ([A-Za-z0-9_.@-]{1,64})\b',msg)
        if session:
            kind='system_session';details.update(operation=session[1],user=session[2]);subject=session[2];description='PAM session transition reported.'
        elif re.search(r'authentication failure|incorrect password|FAILED LOGIN|not in the sudoers|NOT in sudoers|command not allowed',msg,re.I):
            kind='system_auth_failure';review=True;description='Authentication or privilege request failed.'
            user=re.search(r'\buser=([A-Za-z0-9_.@-]{1,64})\b',msg)
            if user:details['user']=user[1];subject=user[1]
        elif program=='sudo' and 'COMMAND=' in msg:
            kind='system_privilege';description='Sudo command reported; command arguments omitted.'
            command=re.search(r'\bCOMMAND=(/[^\s;]{1,200})',msg)
            if command:details['command']=pathlib.PurePosixPath(command[1]).name
        elif program in ('passwd','chpasswd','useradd','userdel','usermod','groupadd','groupdel','groupmod','gpasswd'):
            operations=('new user','delete user','new group','removed group','delete group','change','add','remove','password changed','password updated')
            operation=next((v for v in operations if v in msg.lower()),None)
            if operation:
                kind='system_identity';review=True;description='Account or group management reported; success and authorization require corroboration.';details['operation']=operation
                user=re.search(r"(?:name=|user '?|group '?)([A-Za-z0-9_.@-]{1,64})\b",msg)
                if user:details['account']=user[1];subject=user[1]
        elif program.lower() in ('cron','crond') and re.search(r'\b(CMD|CMDEND|RELOAD|REPLACE|DELETE|ERROR)\b',msg):
            operation=re.search(r'\b(CMD|CMDEND|RELOAD|REPLACE|DELETE|ERROR)\b',msg)[1]
            kind='system_schedule';details['operation']=operation;review=operation in ('ERROR','REPLACE','DELETE');description='Scheduled task activity reported; task arguments omitted.'
        elif program=='systemd':
            unit=re.search(r'\b([A-Za-z0-9_.@:-]+\.(?:service|timer))\b',msg)
            operation=re.search(r'\b(Failed|Started|Stopped|Starting|Stopping|Scheduled restart|Deactivated|Main process exited)\b',msg)
            if unit and operation:
                kind='system_service';subject=unit[1];details.update(unit=unit[1],operation=operation[1]);review=operation[1] in ('Failed','Main process exited');description='System service or timer transition reported.'
    if (program in ('kernel','audit') or 'apparmor=' in msg or 'avc:' in msg) and kind is None:
        if 'apparmor="DENIED"' in msg or re.search(r'avc:\s+denied\b',msg,re.I):
            kind='system_access_denied';review=True;details['mechanism']='AppArmor' if 'apparmor=' in msg else 'SELinux';description='Mandatory access-control denial reported; a denial does not prove compromise.'
        elif re.search(r'Out of memory:|oom-kill:|Killed process \d+',msg):
            kind='system_resource_failure';review=True;description='Kernel memory exhaustion or OOM termination reported.'
        elif re.search(r'\bsegfault at\b',msg):
            kind='system_process_fault';review=True;description='Kernel process fault reported; cause is unconfirmed.'
    if kind is None:return None
    details.update(category=family(program),review_signal=review)
    return {'event_id':event_id,'event_time':stamp,'kind':kind,'subject':subject,'details':details,'description':description}

def journal(record):
    from journal_sources import normalize_boot_id
    program=str(record.get('SYSLOG_IDENTIFIER') or record.get('_COMM',''))
    if record.get('_TRANSPORT')=='kernel':program='kernel'
    try:stamp=int(record['__REALTIME_TIMESTAMP'])/1e6
    except (KeyError,ValueError,TypeError):return None
    boot=normalize_boot_id(record.get('_BOOT_ID'))
    if not boot or not record.get('__CURSOR'):return None
    return parse(program,record.get('MESSAGE'),stamp,'journal:'+record['__CURSOR'],program,boot,record)

def text_record(line,now=None):
    """RFC3164/local-year and ISO timestamp syslog; ambiguous formats are counted."""
    now=time.time() if now is None else now
    match=re.match(r'^(\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+([A-Za-z0-9_.@/-]+)(?:\[\d+\])?:\s?(.*)$',line)
    if not match:return None
    date,program,msg=match.groups()
    try:
        if date[0].isdigit():stamp=datetime.datetime.fromisoformat(date.replace('Z','+00:00')).timestamp();inferred=False
        else:
            local=datetime.datetime.fromtimestamp(now)
            options=[]
            for year in (local.year-1,local.year,local.year+1):
                try:options.append(datetime.datetime.strptime(str(year)+' '+date,'%Y %b %d %H:%M:%S').timestamp())
                except ValueError:pass
            stamp=min(options,key=lambda t:abs(now-t));inferred=True
    except (ValueError,OverflowError):return None
    return program,stamp,msg,inferred

def ingest(engine,event):
    if not event or not -5<=time.time()-event['event_time']<=600:return False
    # File records have no provable boot identity. Never attach a current-boot PID or AUID.
    if event['details'].get('boot_id') not in (None,engine.boot_id):return False
    if not engine.remember(event):return False
    engine.store.observe(event['details']['source'],event['kind'],event['subject'],event['description'],event['event_id'],event['event_time'])
    from telemetry import identity
    ident=identity(event['details'])
    subject=':'.join(ident) if ident else 'system-log:'+event['details']['category']
    if event['details']['review_signal']:
        rows=engine.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind LIKE 'system_%' AND event_time BETWEEN ? AND ? ORDER BY event_time DESC LIMIT 256",(event['event_time']-120,event['event_time'])).fetchall()
        import json
        context=[]
        for eid,stamp,kind,target,raw in rows:
            d=json.loads(raw)
            if (ident and identity(d)==ident) or (not ident and identity(d) is None and d.get('category')==event['details']['category']):
                context.append(engine.normalize(kind,target,d,eid,stamp))
            if len(context)>=32:break
        if ident:
            row=engine.db.execute('SELECT event_id,event_time,details_json FROM ssh_sessions WHERE identity=?',(':'.join(ident),)).fetchone()
            if row and row[1]<=event['event_time']:
                context.append(engine.normalize('ssh_session_open',':'.join(ident),json.loads(row[2]),row[0],row[1]))
        # Single failed login remains an observation; group repeated attempts before analysis.
        if event['kind']!='system_auth_failure' or sum(e['kind']=='system_auth_failure' and e['subject']==event['subject'] and e['details'].get('ip')==event['details'].get('ip') for e in context)>=engine.c.get('ssh_threshold',5):
            engine.create_or_append('system_activity',subject,event,context)
    else:
        row=engine.db.execute("SELECT id FROM cases WHERE kind='system_activity' AND subject=? AND created_at>? ORDER BY created_at DESC LIMIT 1",(subject,time.time()-120)).fetchone()
        if row:engine.create_or_append('system_activity',subject,event,case_id=row[0])
    return True
