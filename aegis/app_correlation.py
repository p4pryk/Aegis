"""Root-owned application telemetry joined with independent kernel audit records."""
import fcntl,json,os,pathlib,re,stat,time,pwd
from vulnerable_app import rpc
LOG='/var/log/defense-agent/application.jsonl'
def ingest(engine):
    try:fd=os.open(engine.c.get('application_log',LOG),os.O_RDONLY|os.O_NOFOLLOW)
    except FileNotFoundError:
        engine.app_health=dict(getattr(engine,'app_health',{}),connected=False,checked_at=time.time());return
    with os.fdopen(fd) as f:
        fcntl.flock(f,fcntl.LOCK_SH)
        with engine.store.atomic():
            st=os.fstat(f.fileno())
            if st.st_uid!=0 or st.st_mode&0o022 or not stat.S_ISREG(st.st_mode):raise ValueError('Untrusted application telemetry')
            h=getattr(engine,'app_health',{});engine.app_health=h
            h.update(connected=True,checked_at=time.time())
            off=engine.store.state('app_offset') or {}
            if off and (off.get('ino')!=st.st_ino or off.get('offset',0)>st.st_size):engine.store.state('app_source_gap',{'time':time.time(),'reason':'file replaced or truncated; continuity cannot be proved'})
            position=off.get('offset',0) if off.get('ino')==st.st_ino and off.get('offset',0)<=st.st_size else 0;f.seek(position)
            for _ in range(100):
                line=f.readline()
                if not line or not line.endswith('\n'):break
                position=f.tell();h['last_received_at']=time.time()
                try:
                    d=json.loads(line)
                    if d['type'] not in ('app_login','app_account_job','app_persistence_job') or d['boot_id']!=engine.boot_id or abs(time.time()-d['time'])>60:continue
                    event=engine.normalize(d['type'],d.get('session') or d['request_id'],d,'app:'+d['event_id'],d['time'])
                    if engine.remember(event):
                        engine.store.observe('application', 'sql_auth_bypass' if d['type']=='app_login' and d['bypass'] else 'sqli_signature' if d['type']=='app_login' and d.get('suspicious') else d['type'],d['ip'],'Database authentication outcome recorded.' if d['type']=='app_login' else 'Application operation completed; awaiting independent audit correlation.',event['event_id'],d['time'])
                        if d['type']=='app_login' and (d['bypass'] or d.get('suspicious')):engine.create_or_append('app_sql_login',event['subject'],event)
                except (ValueError,KeyError,TypeError):
                    h['invalid_records']=h.get('invalid_records',0)+1
                    engine.store.state('app_source_gap',{'time':time.time(),'reason':'invalid application record skipped'})
                    continue
            h['pending_bytes']=max(0,st.st_size-position)
            h['pending_since']=h.get('pending_since') or time.time() if h['pending_bytes'] else None
            h['pending_seconds']=time.time()-h['pending_since'] if h['pending_since'] else 0
            new_offset={'ino':st.st_ino,'offset':position}
            if off!=new_offset:engine.store.state('app_offset',new_offset)
    if time.monotonic()-getattr(engine,'last_app_enrichment',0)<.25:return
    engine.last_app_enrichment=time.monotonic()
    rows=engine.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind IN ('app_account_job','app_persistence_job') AND event_time>?",(time.time()-60,)).fetchall()
    for r in rows:
        job=engine.normalize(r[2],r[3],json.loads(r[4]),r[0],r[1]);jd=job['details']
        if job['kind']=='app_persistence_job':
            from persistence import chain
            chain(engine,job);continue
        loginrow=engine.db.execute('SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE event_id=?',('app:'+jd['login_id'],)).fetchone()
        if not loginrow:continue
        login=engine.normalize(loginrow[2],loginrow[3],json.loads(loginrow[4]),loginrow[0],loginrow[1]);ld=login['details']
        if not ld.get('bypass') or not ld.get('success') or ld.get('session')!=jd.get('session') or ld.get('ip')!=jd.get('ip') or not 0<=job['event_time']-login['event_time']<=600:continue
        producer=engine.recent_exec(jd['pid'],job['event_time'])
        if not producer:continue
        pd=producer['details']
        if pd.get('boot_id')!=jd['boot_id'] or pd.get('ppid')!=jd['broker_pid'] or pd.get('parent_start_ticks')!=jd['broker_start_ticks'] or pd.get('uid')!='0' or pathlib.PurePath(pd.get('exe','')).name!='useradd':continue
        for ar in engine.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind='account_created' AND subject=? AND event_time BETWEEN ? AND ?",(jd['user'],producer['event_time'],job['event_time']+.1)).fetchall():
            account=engine.normalize(ar[2],ar[3],json.loads(ar[4]),ar[0],ar[1]);ad=account['details']
            if ad.get('pid')!=jd['pid'] or ad.get('account_uid')!=jd['account_uid'] or any(ad.get(k)!=pd.get(k) for k in ('boot_id','auid','session')):continue
            engine.create_or_append('app_sql_account',account['event_id'],account,[login,job,producer])
def plan(events,config,boot_id=None):
    login=next((e for e in events if e['kind']=='app_login'),None);job=next((e for e in events if e['kind']=='app_account_job'),None);account=next((e for e in events if e['kind']=='account_created'),None);producer=next((e for e in events if e['kind']=='process_exec'),None)
    if not all((login,job,account,producer)):return [],[],[]
    ld,jd,ad,pd=[e['details'] for e in (login,job,account,producer)]
    if boot_id is not None and jd.get('boot_id')!=boot_id:return [],[],[]
    if not any('aegis-target-broker.service' in line.rsplit(':',1)[-1].split('/') for line in (pd.get('cgroup') or '').splitlines()):return [],[],[]
    if not ld.get('bypass') or not ld.get('success') or ld.get('session')!=jd.get('session') or ld.get('ip')!=jd.get('ip') or jd.get('login_id')!=ld.get('event_id') or not re.fullmatch('[a-f0-9]{32}',ld.get('session','')):return [],[],[]
    if not re.fullmatch(r'lab_http_[a-z0-9_]{1,15}',account['subject']) or account['subject']!=jd.get('user') or account['subject'] in config['protected_users']:return [],[],[]
    if pd.get('pid')!=jd.get('pid') or ad.get('pid')!=jd.get('pid') or pd.get('ppid')!=jd.get('broker_pid') or pd.get('parent_start_ticks')!=jd.get('broker_start_ticks') or pd.get('uid')!='0' or pathlib.PurePath(pd.get('exe','')).name!='useradd' or any(pd.get(k)!=ad.get(k) for k in ('boot_id','auid','session')) or pd.get('boot_id')!=jd.get('boot_id'):return [],[],[]
    if not login['event_time']<=producer['event_time']<=account['event_time']<=job['event_time']+.1 or job['event_time']-producer['event_time']>10 or job['event_time']-login['event_time']>600:return [],[],[]
    try:uid=pwd.getpwnam(account['subject']).pw_uid
    except KeyError:return [],[],[]
    if uid<1000 or uid==65534 or uid!=ad.get('account_uid') or uid!=jd.get('account_uid'):return [],[],[]
    actions=[dict(action='quarantine_account',user=account['subject']),dict(action='revoke_app_session',session=ld['session'])]
    from agent import safe_ip
    if ld['ip'] in config.get('app_dedicated_source_ips',[]) and safe_ip(ld['ip'],config):actions.append(dict(action='block_ip',ip=ld['ip']))
    edges=[{'from':login['event_id'],'to':job['event_id'],'relation':'broker_session_and_login_reference'}, {'from':job['event_id'],'to':producer['event_id'],'relation':'kernel_pid_ppid_boot_and_broker_start_ticks'}, {'from':producer['event_id'],'to':account['event_id'],'relation':'same_boot_producer_pid_auid_session'}]
    return actions,[e['event_id'] for e in (login,job,producer,account)],edges
