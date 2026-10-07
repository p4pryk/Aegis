"""Bounded audit assembly, persistence observation and scoped containment."""
import hashlib,json,os,pathlib,re,stat,time

QUARANTINE = pathlib.Path('/var/lib/defense-agent/quarantine')

def scope(path):
    p=pathlib.PurePosixPath(path)
    if not p.is_absolute() or '..' in p.parts:return None
    if p.name=='authorized_keys' and p.parent.name=='.ssh':return 'ssh_key'
    if str(p)=='/etc/crontab' or str(p.parent)=='/etc/cron.d':return 'cron'
    if str(p.parent)=='/etc/systemd/system' and p.suffix=='.service':return 'systemd'

def lab_path(path):
    return bool(re.fullmatch(r'/etc/cron.d/lab_aegis_[a-z0-9_]{1,20}|/etc/systemd/system/lab-aegis-[a-z0-9-]{1,20}\.service',path))

def fingerprint(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>65536:raise ValueError('Untrusted persistence file')
        return hashlib.sha256(f.read()).hexdigest(),(info.st_dev,info.st_ino)

def inactive(path):
    import subprocess
    code=subprocess.run(['systemctl','is-active','--quiet',pathlib.Path(path).name]).returncode
    if code not in (3,4):raise RuntimeError('Service inactivity not verified')

def quarantine(request):
    from agent import run
    if set(request)!={'action','path','sha256'} or not lab_path(request['path']):raise ValueError('Persistence target outside training scope')
    path=request['path'];digest=request['sha256']
    backup=QUARANTINE;backup.mkdir(mode=0o700,exist_ok=True)
    target=backup/(pathlib.Path(path).name+'.'+digest)
    if not os.path.lexists(path):
        if fingerprint(target)[0]!=digest:raise ValueError('Quarantine backup does not match')
        if scope(path)=='systemd':
            run(['systemctl','stop',pathlib.Path(path).name],ok=(0,5))
            run(['systemctl','daemon-reload'])
            inactive(path)
        return {'verified':True,'path':path,'sha256':digest,'backup':str(target),'removed_from_active_path':True,'already_quarantined':True}
    current_digest,identity=fingerprint(path)
    if current_digest!=digest:raise ValueError('Persistence file changed after assessment')
    if scope(path)=='systemd':
        run(['systemctl','disable','--now',pathlib.Path(path).name])
    current=os.lstat(path)
    if (current.st_dev,current.st_ino)!=identity or fingerprint(path)[0]!=digest:raise ValueError('Persistence identity changed')
    # Same filesystem on the lab VM. Preserve the evidence, do not delete it.
    os.rename(path,target)
    if scope(path)=='systemd':run(['systemctl','daemon-reload'])
    if os.path.lexists(path) or fingerprint(target)[0]!=digest:raise RuntimeError('Persistence quarantine not verified')
    if scope(path)=='systemd':inactive(path)
    return {'verified':True,'path':path,'sha256':digest,'backup':str(target),'removed_from_active_path':True}

def audit(engine,kind,stamp,serial,content):
    if kind not in ('SYSCALL','1300','PATH','1302','EOE','1320'):return
    now=time.monotonic();pending=getattr(engine,'persistence_pending',{});engine.persistence_pending=pending
    expired=[k for k,v in pending.items() if now-v['received']>2]
    for key in expired:pending.pop(key)
    if expired:engine.store.state('persistence_incomplete',{'time':time.time(),'expired_groups':len(expired)})
    key=engine.boot_id+':'+stamp+':'+serial
    if kind in ('SYSCALL','1300'):
        if 'aegis_persistence' not in content:return
        fields=dict(re.findall(r'(\w+)=("[^"]*"|\S+)',content));fields={k:v.strip('"') for k,v in fields.items()}
        if fields.get('success')!='yes':return
        if len(pending)>=512:engine.store.state('persistence_overload',{'time':time.time()});return
        from agent import process_snapshot
        pid=int(fields['pid']);snap=process_snapshot(pid) or {}
        pending[key]={'received':now,'paths':[],'details':{'pid':pid,'boot_id':engine.boot_id,'uid':fields.get('uid'),'auid':fields.get('auid'),'session':fields.get('ses'),'exe':fields.get('exe'),'start_ticks':snap.get('start_ticks'),'cgroup':snap.get('cgroup')}}
    elif kind in ('PATH','1302') and key in pending:
        match=re.search(r'\bname=("[^"]*"|\S+)',content)
        if not match:return
        value=match[1]
        try:path=value[1:-1] if value.startswith('"') else bytes.fromhex(value).decode()
        except (ValueError,UnicodeError):return
        if scope(path) and len(pending[key]['paths'])<16:pending[key]['paths'].append((path,re.search(r'\bnametype=(\w+)',content)[1] if re.search(r'\bnametype=(\w+)',content) else 'UNKNOWN'))
    elif kind in ('EOE','1320') and key in pending:
        group=pending.pop(key)
        for path,operation in set(group['paths']):
            details=dict(group['details'],path=path,operation=operation,mechanism=scope(path))
            event=engine.normalize('persistence_change',path,details,key+':file:'+hashlib.sha256(path.encode()).hexdigest()[:8],float(stamp))
            if engine.remember(event):
                engine.store.observe('auditd','persistence_change',path,'Persistence-related file changed; awaiting actor and session correlation.',event['event_id'],event['event_time'])
                if operation not in ('DELETE','DELETED'):engine.create_or_append('persistence_change',path,event)

def chain(engine,job):
    d=job['details'];row=engine.db.execute('SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE event_id=?',('app:'+d['login_id'],)).fetchone()
    if not row:return
    login=engine.normalize(row[2],row[3],json.loads(row[4]),row[0],row[1]);ld=login['details']
    if not ld.get('bypass') or not ld.get('success') or ld.get('session')!=d.get('session') or ld.get('ip')!=d.get('ip'):return
    for r in engine.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind='persistence_change' AND subject=? AND event_time BETWEEN ? AND ?",(d['path'],job['event_time']-5,job['event_time']+.1)):
        mutation=engine.normalize(r[2],r[3],json.loads(r[4]),r[0],r[1])
        if plan([login,mutation,job],engine.c,engine.boot_id)[0]:
            case_id=engine.create_or_append('app_sql_persistence',job['event_id'],job,[login,mutation])
            generic=engine.db.execute("SELECT id FROM cases WHERE kind='persistence_change' AND subject=? AND status NOT IN ('superseded','defended') ORDER BY created_at DESC LIMIT 1",(d['path'],)).fetchone()
            if case_id and generic:engine.status(generic[0],'superseded',{'linked_case':case_id})
            return

def plan(events,config,boot_id):
    login=next((e for e in events if e['kind']=='app_login'),None);mutation=next((e for e in events if e['kind']=='persistence_change'),None);job=next((e for e in events if e['kind']=='app_persistence_job'),None)
    if not all((login,mutation,job)):return [],[],[]
    ld,md,jd=[e['details'] for e in (login,mutation,job)]
    if not ld.get('bypass') or not ld.get('success') or ld.get('session')!=jd.get('session') or ld.get('ip')!=jd.get('ip') or jd.get('login_id')!=ld.get('event_id') or not re.fullmatch('[a-f0-9]{32}',ld.get('session','')):return [],[],[]
    if jd.get('boot_id')!=boot_id or md.get('boot_id')!=boot_id or md.get('pid')!=jd.get('broker_pid') or md.get('start_ticks')!=jd.get('broker_start_ticks') or md.get('uid')!='0' or 'aegis-target-broker.service' not in (md.get('cgroup') or '').split('/')[-1].strip():return [],[],[]
    path=jd.get('path','')
    if md.get('path')!=path or not lab_path(path) or not login['event_time']<=mutation['event_time']<=job['event_time']+.1 or not 0<=job['event_time']-mutation['event_time']<=5 or job['event_time']-login['event_time']>600:return [],[],[]
    try:digest,_=fingerprint(path)
    except (OSError,ValueError):return [],[],[]
    if digest!=jd.get('sha256'):return [],[],[]
    actions=[{'action':'quarantine_persistence','path':path,'sha256':digest},{'action':'revoke_app_session','session':ld['session']}]
    edges=[{'from':login['event_id'],'to':job['event_id'],'relation':'broker_session_and_login_reference'},{'from':mutation['event_id'],'to':job['event_id'],'relation':'kernel_writer_pid_boot_start_ticks_and_exact_path'}]
    return actions,[e['event_id'] for e in (login,mutation,job)],edges
