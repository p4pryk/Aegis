"""Application-independent, metadata-only file adapters. All producer claims are untrusted."""
import datetime,hashlib,ipaddress,json,math,pathlib,re,stat,time
from file_logs import Files
from journal_sources import sqli_signature,web_request_signals

FIELDS=('time','event','outcome','user','ip','request_id','session_id','method','path','status')
EVENTS=('http_request','authentication','account_created','permission_changed','security_alert','application_error')
ACCESS=re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]{3,10}) (\S+) HTTP/[0-9.]+" ([0-9]{3}) (?:\d+|-)(?: "[^"\r\n]*" "[^"\r\n]*")?\s*$')
NAME=re.compile(r'[A-Za-z0-9_.-]{1,64}')

def sources(config):
    result={};paths=set();items=config.get('application_sources',[])
    if not isinstance(items,list) or len(items)>8:raise ValueError('application_sources must contain at most eight sources')
    items=list(items)
    if config.get('auto_access_logs',True):
        for application,path in (('nginx','/var/log/nginx/access.log'),('apache','/var/log/apache2/access.log'),('httpd','/var/log/httpd/access_log')):
            if len(items)>=8:break
            if any(item.get('path')==path or item.get('name')=='auto-'+application for item in items if isinstance(item,dict)):continue
            try:info=pathlib.Path(path).lstat()
            except OSError:continue
            if stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022:
                items.append(dict(name='auto-'+application,application=application,path=path,format='access'))
    for item in items:
        if not isinstance(item,dict) or set(item)-{'name','application','path','format','owner_uid','fields','events'}:raise ValueError('Invalid application source configuration')
        source=dict(item)
        for field in ('name','application'):
            if not isinstance(source.get(field),str) or not NAME.fullmatch(source[field]):raise ValueError('Invalid application source name')
        path=source.get('path','');owner=source.setdefault('owner_uid',0)
        if not isinstance(path,str) or not pathlib.PurePosixPath(path).is_absolute() or '..' in pathlib.PurePosixPath(path).parts or '\x00' in path:raise ValueError('Application paths must be absolute')
        if source['name'] in result or path in paths:raise ValueError('Duplicate application source name/path')
        if type(owner) is not int or not 0<=owner<4294967295:raise ValueError('Invalid log owner UID')
        if source.get('format') not in ('jsonl','access'):raise ValueError('Supported application formats: jsonl, access')
        mapping=source.setdefault('fields',{});events=source.setdefault('events',{})
        if not isinstance(mapping,dict) or set(mapping)-set(FIELDS) or any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',v) for v in mapping.values()):raise ValueError('Invalid application field mapping')
        if not isinstance(events,dict) or len(events)>32 or any(not isinstance(k,str) or len(k)>128 or v not in EVENTS for k,v in events.items()):raise ValueError('Invalid event mapping')
        result[source['name']]=source;paths.add(path)
    return result

def timestamp(value):
    if isinstance(value,str):
        if not re.search(r'[TZ:+]',value):return float(value)
        parsed=datetime.datetime.fromisoformat(value.replace('Z','+00:00'))
        if parsed.tzinfo is None:raise ValueError('Timestamp requires a timezone')
        return parsed.timestamp()
    if type(value) not in (int,float):raise ValueError('Invalid timestamp')
    return float(value)

def token(value):
    if not isinstance(value,str) or not 1<=len(value)<=256 or any(ord(c)<33 or ord(c)>126 for c in value):return None
    return hashlib.sha256(value.encode()).hexdigest()

def parse(raw,source,identifier):
    if len(raw)>8192:raise ValueError('Oversized application record')
    if source['format']=='access':
        match=ACCESS.fullmatch(raw.strip())
        if not match:return None
        stamp=datetime.datetime.strptime(match[2],'%d/%b/%Y:%H:%M:%S %z').timestamp()
        record=dict(time=stamp,event='http_request',ip=match[1],method=match[3],path=match[4],status=int(match[5]))
    else:
        data=json.loads(raw)
        if not isinstance(data,dict):raise ValueError('Expected a JSON object')
        record={}
        for field in FIELDS:
            value=data
            for part in source.get('fields',{}).get(field,field).split('.'):
                value=value.get(part) if isinstance(value,dict) else None
            if value is not None:record[field]=value
    event=record.get('event')
    if not isinstance(event,str):return None
    event=source.get('events',{}).get(event,event)
    if event not in EVENTS:return None
    stamp=timestamp(record.get('time'))
    if not math.isfinite(stamp):raise ValueError('Invalid timestamp')
    d=dict(application=source['application'],source=source['name'],transport='application_file',event=event,identity_verified=False,trust='producer_reported_not_independently_verified')
    outcome=record.get('outcome')
    if outcome is not None:
        if outcome not in ('success','failure','unknown'):raise ValueError('Invalid outcome')
        d['outcome']=outcome
    user=record.get('user')
    if user is not None:
        if not isinstance(user,str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}',user):raise ValueError('Invalid user')
        d['user']=user
    if record.get('ip') is not None:
        if not isinstance(record['ip'],str):raise ValueError('Invalid IP')
        d['ip']=str(ipaddress.ip_address(record['ip']))
    for field in ('request_id','session_id'):
        if record.get(field) is not None:
            value=token(record[field])
            if value is None:raise ValueError('Invalid correlation identifier')
            d[field+'_hash']=value
    if record.get('method') is not None:
        if not isinstance(record['method'],str) or not re.fullmatch('[A-Z]{3,10}',record['method']):raise ValueError('Invalid method')
        d['method']=record['method']
    if record.get('status') is not None:
        status=record['status']
        if isinstance(status,str) and re.fullmatch('[1-5][0-9]{2}',status):status=int(status)
        if type(status) is not int or not 100<=status<=599:raise ValueError('Invalid HTTP status')
        d['status']=status
    path=record.get('path')
    if path is not None:
        if not isinstance(path,str) or len(path)>4096 or not path.startswith('/') or any(ord(c)<32 for c in path):raise ValueError('Invalid request target')
        # Query/body/headers are never persisted. Paths may contain identifiers: retain only a hash.
        d['path_hash']=hashlib.sha256(path.split('?',1)[0].split('#',1)[0].encode()).hexdigest()
        d['sqli_signature']=sqli_signature(path)
        signals=web_request_signals(path)
        if signals:d['web_signals']=signals
    d['review_signal']=bool(d.get('sqli_signature') or d.get('web_signals') or event in ('account_created','permission_changed','security_alert','application_error'))
    return dict(event_id=identifier,event_time=stamp,kind='application_event',subject=source['application'],details=d)

def auth_records(engine,app,user,ip,outcome,start,end,limit=30,exclusive_end=False):
    operator='<' if exclusive_end else '<='
    rows=engine.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events INDEXED BY correlation_app_auth_lookup WHERE kind='application_event' AND subject=? AND json_extract(details_json,'$.event')='authentication' AND json_extract(details_json,'$.user')=? AND json_extract(details_json,'$.ip')=? AND json_extract(details_json,'$.outcome')=? AND event_time>=? AND event_time"+operator+"? ORDER BY event_time DESC LIMIT ?",(app,user,ip,outcome,start,end,limit)).fetchall()
    return [engine.normalize(r[2],r[3],json.loads(r[4]),r[0],r[1]) for r in rows]

def auth_chain(events):
    unique={e['event_id']:e for e in events if e['kind']=='application_event' and e['details'].get('event')=='authentication'}
    ordered=sorted(unique.values(),key=lambda e:(e['event_time'],e['event_id']))
    for success in reversed(ordered):
        d=success['details']
        if d.get('outcome')!='success' or not d.get('user') or not d.get('ip'):continue
        failures=[e for e in ordered if e['details'].get('outcome')=='failure' and e['subject']==success['subject'] and e['details'].get('user')==d['user'] and e['details'].get('ip')==d['ip'] and 0<success['event_time']-e['event_time']<=300]
        if len(failures)>=5:return success,failures
    return None,[]

def auth_signals(events):
    success,failures=auth_chain(events)
    return [{'kind':'reported_app_success_after_failures','failure_count':len(failures)}] if success else []

def ingest(engine,event):
    if not -5<=time.time()-event['event_time']<=600:return
    if not engine.remember(event):return
    d=event['details'];app=event['subject']
    engine.store.observe('application:'+d['source'],'application_signal' if d['review_signal'] else 'application_event',app,'Application-reported '+d['event']+'; outcome '+d.get('outcome','unknown')+'. No containment authorized.',event['event_id'],event['event_time'])
    rows=engine.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind='application_event' AND subject=? AND event_time BETWEEN ? AND ? ORDER BY event_time DESC LIMIT 256",(app,time.time()-600,time.time()+5)).fetchall()
    recent=[engine.normalize(r[2],r[3],json.loads(r[4]),r[0],r[1]) for r in rows]
    auth=d['event']=='authentication' and d.get('outcome') in ('failure','success') and d.get('user') and d.get('ip')
    failures=auth_records(engine,app,d['user'],d['ip'],'failure',event['event_time']-300,event['event_time'],exclusive_end=d['outcome']=='success') if auth else []
    # Session claims partition evidence; they never establish trusted attribution.
    def scope(details):
        if details.get('session_id_hash'):return 'session:'+details['session_id_hash']
        request=details.get('request_id_hash')
        matches={e['details']['session_id_hash'] for e in recent if request and e['details'].get('request_id_hash')==request and e['details'].get('session_id_hash')}
        if len(matches)==1:return 'session:'+next(iter(matches))
        if request:return 'request:'+request
        if details.get('user'):return 'user:'+details['user']+':'+details.get('ip','')
        return 'unattributed'
    group=scope(d);subject=app+':'+hashlib.sha256(group.encode()).hexdigest()[:24]
    existing=engine.db.execute("SELECT id FROM cases WHERE kind='application_activity' AND subject=? AND created_at>? AND status NOT IN ('defended','recognized','defense_error') ORDER BY created_at DESC LIMIT 1",(subject,time.time()-120)).fetchone()
    related=[e for e in recent if scope(e['details'])==group]
    if d['review_signal'] or existing or len(failures)>=5:
        selected={e['event_id']:e for e in [event,*failures,*related]}
        engine.create_or_append('application_activity',subject,event,list(selected.values())[:32])
    # A delayed failure can complete an earlier-received success without relying on arrival order.
    if auth and d['outcome']=='failure':
        for success in auth_records(engine,app,d['user'],d['ip'],'success',event['event_time'],min(event['event_time']+300,time.time()+5),16):
            if success['event_time']<=event['event_time']:continue
            prior=auth_records(engine,app,d['user'],d['ip'],'failure',success['event_time']-300,success['event_time'],exclusive_end=True)
            if len(prior)<5:continue
            group=scope(success['details']);target=app+':'+hashlib.sha256(group.encode()).hexdigest()[:24]
            context=[e for e in recent if scope(e['details'])==group]
            selected={e['event_id']:e for e in [success,*prior,*context]}
            current=engine.db.execute("SELECT p.root_id FROM cases c JOIN case_parts p ON p.case_id=c.id WHERE c.kind='application_activity' AND c.subject=? AND c.created_at>? AND c.status NOT IN ('defended','recognized','defense_error','superseded') ORDER BY c.created_at DESC LIMIT 1",(target,time.time()-max(120,min(3600,int(engine.c.get('incident_context_seconds',3600)))))).fetchone()
            fresh=success if not current else next((e for e in [success,*prior] if not engine.db.execute('SELECT 1 FROM case_events e JOIN case_parts p ON p.case_id=e.case_id WHERE p.root_id=? AND e.event_id=? LIMIT 1',(current[0],e['event_id'])).fetchone()),None)
            if fresh:engine.create_or_append('application_activity',target,fresh,list(selected.values())[:32])

def carry_context(events):
    """Keep representative signals and recent context without growing model input."""
    anchors={}
    for event in events:
        d=event['details']
        key=('authentication',d.get('outcome')) if d.get('event')=='authentication' else ('sqli',) if d.get('sqli_signature') else ('web_probe',) if d.get('web_signals') else (d.get('event'),)
        if d.get('review_signal') or d.get('event')=='authentication':anchors[key]=event
    success,failures=auth_chain(events)
    auth=[*failures[-5:],success] if success else []
    priority=[anchors[key] for key in (('account_created',),('permission_changed',),('sqli',),('web_probe',)) if key in anchors]
    selected={e['event_id']:e for e in ([*auth,*priority,*events[-2:],*list(anchors.values())[:6]] if auth else [*list(anchors.values())[:6],*events[-2:]])}
    return list(selected.values())[:8]

def links(events):
    result=[];seen={};pairs=set()
    for event in sorted(events,key=lambda e:(e['event_time'],e['event_id'])):
        if event['kind']!='application_event':continue
        d=event['details']
        for field in ('request_id_hash','session_id_hash'):
            if not d.get(field):continue
            key=(d['application'],field,d[field]);prior=seen.get(key)
            if prior and 0<=event['event_time']-prior['event_time']<=600 and (prior['event_id'],event['event_id']) not in pairs:
                pairs.add((prior['event_id'],event['event_id']))
                result.append(dict(from_=prior['event_id'],to=event['event_id'],relation='application_reported_'+field+'_not_causal'))
                result[-1]['from']=result[-1].pop('from_')
            seen[key]=event
    success,failures=auth_chain(events)
    if success:
        result.extend({'from':failure['event_id'],'to':success['event_id'],'relation':'same_reported_application_account_ip_prior_failure_not_causal'} for failure in failures)
    return result

class Applications(Files):
    def __init__(self,engine):
        self.config=sources(engine.c)
        super().__init__(engine,{name:s['path'] for name,s in self.config.items()})
    def trusted(self,info,path):
        owner=next(s['owner_uid'] for s in self.config.values() if s['path']==path)
        return stat.S_ISREG(info.st_mode) and info.st_uid==owner and not info.st_mode&0o022
    def cursor_key(self,category,path):
        return 'application_cursor_'+hashlib.sha256(json.dumps(self.config[category],sort_keys=True).encode()).hexdigest()[:24]
    def accept(self,category,raw,identifier,now,available,h):
        try:
            identifier='application:'+hashlib.sha256((self.cursor_key(category,self.paths[category])+identifier).encode()).hexdigest()
            event=parse(raw.decode('utf-8'),self.config[category],identifier)
            if event is None:h['unrecognized']+=1;return
            if not -5<=now-event['event_time']<=600:h['stale']+=1;return
        except (ValueError,TypeError,OverflowError,RecursionError):h['invalid']+=1;return
        ingest(self.engine,event);h['parsed']+=1
    def sources(self):
        return [dict(h,name='App '+name,application=self.config[name]['application'],format=self.config[name]['format']) for name,h in self.health.items()]
