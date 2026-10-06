#!/usr/bin/env python3
"""Local policy engine. No model output is executable input."""
import argparse, collections, signal, grp, hashlib, ipaddress, json, os, pathlib, pwd, re, socket, sqlite3, stat, struct, subprocess, threading, time

JOURNAL_HEALTH = {'dropped_events':0,'connected':False}

DEFAULTS = dict(mode='correlated', protected_ips=[], protected_users=['root','labadmin'], ssh_threshold=5, ssh_window=30, block_seconds=600, data_dir='/var/lib/defense-agent', runtime_dir='/run/defense-agent', audit_socket='/run/defense-agent/audit.sock', executor_socket='/run/defense-agent/executor.sock')

def run(args, ok=(0,)):
    p = subprocess.run(args, capture_output=True, text=True, timeout=10)
    if p.returncode not in ok:
        raise RuntimeError(f'{args[0]} failed ({p.returncode}): {p.stderr[:300]}')
    return p.stdout

def safe_ip(value, config):
    try: ip = ipaddress.ip_address(value)
    except (ValueError,TypeError): return None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or str(ip) in config['protected_ips']: return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return safe_ip(str(ip.ipv4_mapped), config)
    return str(ip)

def trusted_file(path):
    s = os.lstat(path)
    return stat.S_ISREG(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022

def ssh_response_user(user,config):
    return user in config.get('ssh_response_users',[]) or bool(config.get('ssh_lab_users_enabled',False) and re.fullmatch(r'lab_[a-z0-9_]{1,24}',user))

def audit_processes(boot_id,session,auid):
    if type(session) is not int or type(auid) is not int or session<0 or session>=4294967295 or auid<1000 or auid==65534:raise ValueError('invalid session identity')
    if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot_id:raise ValueError('session belongs to previous boot')
    result=[]
    for base in pathlib.Path('/proc').iterdir():
        if not base.name.isdigit():continue
        try:
            if int((base/'sessionid').read_text())==session and int((base/'loginuid').read_text())==auid:
                snap=process_snapshot(int(base.name))
                if snap and snap['pid']>1:result.append(snap)
        except (OSError,ValueError):continue
    return result

class Executor:
    def __init__(self, config): self.c=config
    def firewall_init(self):
        # Only this table is managed; never alter unrelated firewall rules.
        exists = subprocess.run(['nft','list','table','inet','defense_lab'],capture_output=True).returncode == 0
        if not exists:
            rules="""table inet defense_lab {
    set blocked4 {
        type ipv4_addr
        flags timeout
    }
    set blocked6 {
        type ipv6_addr
        flags timeout
    }
    chain ingress {
        type filter hook input priority -10; policy accept;
        ip saddr @blocked4 counter drop
        ip6 saddr @blocked6 counter drop
    }
}
"""
            p=subprocess.run(['nft','-f','-'],input=rules,text=True,capture_output=True)
            if p.returncode: raise RuntimeError(p.stderr)
    def execute(self, request):
        if request.get('action') == 'quarantine_persistence':
            from persistence import quarantine
            return quarantine(request)
        if request.get('action') == 'revoke_app_session':
            if set(request)!={'action','session'} or not re.fullmatch('[a-f0-9]{32}',request.get('session','')):raise ValueError('Invalid application session')
            from vulnerable_app import rpc
            result=rpc({'op':'revoke','session':request['session']})
            if result.get('verified') is not True:raise RuntimeError('Application session revocation not verified')
            return result
        if request.get('action') == 'block_ip':
            ip=safe_ip(request.get('ip'),self.c)
            if not ip: raise ValueError('protected or invalid IP')
            ttl=int(self.c['block_seconds'])
            if not 1 <= ttl <= 3600: raise ValueError('invalid TTL')
            family='blocked4' if ipaddress.ip_address(ip).version==4 else 'blocked6'
            # add is idempotent while present; don't reset expiry on repeated incident.
            present=subprocess.run(['nft','get','element','inet','defense_lab',family,'{',ip,'}'],capture_output=True).returncode==0
            if not present: run(['nft','add','element','inet','defense_lab',family,'{',ip,'timeout',f'{ttl}s','}'])
            run(['nft','get','element','inet','defense_lab',family,'{',ip,'}'])
            return dict(verified=True,ip=ip,ttl=ttl,already_present=present)
        if request.get('action') == 'terminate_session':
            if set(request)!={'action','boot_id','session','auid','user'}:raise ValueError('invalid session fields')
            user=request['user'];account=pwd.getpwnam(user)
            if user in self.c['protected_users'] or account.pw_uid!=request['auid']:raise ValueError('protected session')
            if not ssh_response_user(user,self.c):raise ValueError('session outside response scope')
            processes=audit_processes(request['boot_id'],request['session'],request['auid'])
            killed=[]
            for proc in processes:
                try:
                    fd=os.pidfd_open(proc['pid'])
                    try:
                        current=process_snapshot(proc['pid']);base=pathlib.Path('/proc')/str(proc['pid'])
                        if current and current['start_ticks']==proc['start_ticks'] and int((base/'sessionid').read_text())==request['session'] and int((base/'loginuid').read_text())==request['auid']:
                            signal.pidfd_send_signal(fd,signal.SIGKILL);killed.append(proc['pid'])
                    finally:os.close(fd)
                except ProcessLookupError:continue
                except FileNotFoundError:continue
            deadline=time.monotonic()+2
            while audit_processes(request['boot_id'],request['session'],request['auid']) and time.monotonic()<deadline:time.sleep(.05)
            remaining=audit_processes(request['boot_id'],request['session'],request['auid'])
            if remaining:raise RuntimeError('session termination not verified')
            return dict(verified=True,session=request['session'],auid=request['auid'],user=user,killed_pids=killed,already_closed=not processes)
        if request.get('action') == 'quarantine_account':
            name=request.get('user','')
            if not re.fullmatch(r'lab_[a-z0-9_]{1,24}',name) or name in self.c['protected_users']: raise ValueError('account outside lab policy')
            account=pwd.getpwnam(name)
            if account.pw_uid<1000 or account.pw_uid==65534 or account.pw_uid==os.getuid() and os.getuid()!=0: raise ValueError('protected uid')
            # Only local accounts, never modify directory users.
            local=[x.split(':') for x in pathlib.Path('/etc/passwd').read_text().splitlines()]
            if not any(x[0]==name and int(x[2])==account.pw_uid for x in local): raise ValueError('not a local account')
            run(['usermod','-L','-s','/usr/sbin/nologin','-e','1970-01-02',name])
            # terminate existing sessions/processes; no username interpolation in shell.
            run(['pkill','-KILL','-u',str(account.pw_uid)],ok=(0,1))
            updated=pwd.getpwnam(name)
            shadow=next(x.split(':') for x in pathlib.Path('/etc/shadow').read_text().splitlines() if x.split(':')[0]==name)
            p=subprocess.run(['pgrep','-u',str(account.pw_uid)],capture_output=True)
            verified=updated.pw_shell=='/usr/sbin/nologin' and shadow[1].startswith('!') and shadow[7]=='1' and p.returncode==1
            if not verified: raise RuntimeError('quarantine verification failed')
            return dict(verified=True,user=name,uid=account.pw_uid,locked=True,expired=True,no_processes=True)
        raise ValueError('unknown action')

class Store:
    def __init__(self,c):
        self.path=pathlib.Path(c['data_dir'])/'incidents.db'
        self.db=sqlite3.connect(self.path)
        self.db.execute('PRAGMA journal_mode=DELETE')
        self.db.executescript('CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT);')
        self.db.executescript('CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY, time REAL, source TEXT, kind TEXT, subject TEXT, description TEXT); CREATE TABLE IF NOT EXISTS sensor_metrics(source TEXT PRIMARY KEY, total INTEGER, last_event REAL);')
        self.db.commit(); os.chmod(self.path,0o640)
        try: os.chown(self.path,0,grp.getgrnam('defense-ai').gr_gid)
        except KeyError: pass
    def state(self,key,value=None):
        if value is None:
            row=self.db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone(); return json.loads(row[0]) if row else None
        self.db.execute('INSERT OR REPLACE INTO state VALUES (?,?)',(key,json.dumps(value))); self.db.commit()
    def observe(self,source,kind,subject,description,event_id,timestamp=None):
        identifier=hashlib.sha256((source+':'+event_id).encode()).hexdigest()[:24]
        now=time.time()
        cursor=self.db.execute('INSERT OR IGNORE INTO observations VALUES (?,?,?,?,?,?)',(identifier,timestamp or now,source,kind,str(subject)[:100],description[:300]))
        if cursor.rowcount:
            self.db.execute('INSERT INTO sensor_metrics VALUES (?,?,?) ON CONFLICT(source) DO UPDATE SET total=total+1,last_event=excluded.last_event',(source,1,now))
            self.db.execute('DELETE FROM observations WHERE rowid NOT IN (SELECT rowid FROM observations ORDER BY rowid DESC LIMIT 2000)')
            print(json.dumps({'event':kind,'source':source,'subject':str(subject)[:100],'description':description[:300]},ensure_ascii=False),flush=True)
        # Telemetry is committed in one batch per core loop; reactions retain their immediate commits.

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)

def process_snapshot(pid):
    try:
        base=pathlib.Path('/proc')/str(int(pid))
        raw=(base/'stat').read_text();tail=raw[raw.rfind(')')+2:].split()
        return {'pid':int(pid),'ppid':int(tail[1]),'start_ticks':int(tail[19]),'cgroup':(base/'cgroup').read_text()[:4096]}
    except (OSError,ValueError,IndexError):return None

class CorrelatedEngine:
    """Root evidence producer. Descriptions gate actions, never create permissions."""
    def __init__(self,c,store,execute):
        self.c=c;self.store=store;self.db=store.db;self.execute=execute
        self.boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() if pathlib.Path('/proc/sys/kernel/random/boot_id').exists() else 'test-boot'
        self.db.executescript('''CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,created_at REAL,updated_at REAL,kind TEXT,subject TEXT,version INTEGER,status TEXT,evidence_json TEXT,analysis_json TEXT,result_json TEXT);
        CREATE TABLE IF NOT EXISTS case_events(case_id TEXT,event_id TEXT,event_time REAL,kind TEXT,subject TEXT,details_json TEXT,PRIMARY KEY(case_id,event_id));
        CREATE TABLE IF NOT EXISTS case_status_history(case_id TEXT,status TEXT,time REAL,details_json TEXT);
        CREATE TABLE IF NOT EXISTS correlation_events(event_id TEXT PRIMARY KEY,event_time REAL,kind TEXT,subject TEXT,details_json TEXT);
        CREATE INDEX IF NOT EXISTS correlation_time ON correlation_events(event_time);
        CREATE INDEX IF NOT EXISTS correlation_subject_time ON correlation_events(kind,subject,event_time);
        CREATE INDEX IF NOT EXISTS correlation_kind_time ON correlation_events(kind,event_time);
        CREATE INDEX IF NOT EXISTS case_history_lookup ON case_status_history(case_id,time);
        CREATE TABLE IF NOT EXISTS pending_account_resolution(event_id TEXT PRIMARY KEY,event_time REAL,details_json TEXT,deadline REAL);
        CREATE TABLE IF NOT EXISTS ssh_sessions(identity TEXT PRIMARY KEY,event_id TEXT,event_time REAL,details_json TEXT,active INTEGER);''');self.db.commit()
        self.last_cleanup=0;self.last_session_reconcile=0
    def status(self,identifier,status,details=None):
        now=time.time();self.db.execute('UPDATE cases SET status=?,updated_at=? WHERE id=?',(status,now,identifier));self.db.execute('INSERT INTO case_status_history VALUES (?,?,?,?)',(identifier,status,now,canonical(details or {})));self.db.commit()
    def events(self,identifier):
        return [dict(event_id=r[0],event_time=r[1],kind=r[2],subject=r[3],details=json.loads(r[4])) for r in self.db.execute('SELECT event_id,event_time,kind,subject,details_json FROM case_events WHERE case_id=? ORDER BY event_time,event_id',(identifier,))]
    def remember(self,event):
        cur=self.db.execute('INSERT OR IGNORE INTO correlation_events VALUES (?,?,?,?,?)',(event['event_id'],event['event_time'],event['kind'],event['subject'],canonical(event['details'])));self.db.commit();return bool(cur.rowcount)
    def create_or_append(self,kind,subject,event,extra=()):
        now=time.time()
        row=self.db.execute("SELECT id FROM cases WHERE kind=? AND subject=? AND created_at>? AND status NOT IN ('defended','recognized') ORDER BY created_at DESC LIMIT 1",(kind,subject,now-120)).fetchone()
        identifier=row[0] if row else hashlib.sha256((kind+':'+subject+':'+event['event_id']).encode()).hexdigest()[:24]
        if not row:
            # Enrichment can revisit the same account after containment. Keep the
            # immutable completed case instead of inserting its deterministic ID again.
            if self.db.execute('SELECT 1 FROM cases WHERE id=?',(identifier,)).fetchone():return identifier
            active=self.db.execute("SELECT count(*) FROM cases WHERE status IN ('collecting','awaiting_analysis','recognized')").fetchone()[0]
            if active>=256:
                self.store.state('correlation_overload',{'time':now,'active_cases':active});return None
            self.db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',(identifier,now,now,kind,subject,0,'collecting','{}','{}','{}'));self.db.execute('INSERT INTO case_status_history VALUES (?,?,?,?)',(identifier,'collecting',now,'{}'))
        changed=False
        for e in [*extra,event]:
            count=self.db.execute('SELECT count(*) FROM case_events WHERE case_id=?',(identifier,)).fetchone()[0]
            if count>=256:break
            cur=self.db.execute('INSERT OR IGNORE INTO case_events VALUES (?,?,?,?,?,?)',(identifier,e['event_id'],e['event_time'],e['kind'],e['subject'],canonical(e['details'])));changed|=bool(cur.rowcount)
        if changed:
            self.db.execute("UPDATE cases SET updated_at=?,version=version+1,status='collecting',analysis_json='{}',result_json='{}' WHERE id=?",(now,identifier));self.db.execute('INSERT INTO case_status_history VALUES (?,?,?,?)',(identifier,'collecting',now,canonical({'reason':'new evidence invalidates analysis'})))
        self.db.commit();return identifier
    def normalize(self,kind,subject,details,event_id,timestamp):
        if len(event_id)>80:event_id='ev:'+hashlib.sha256(event_id.encode()).hexdigest()[:32]
        return {'event_id':event_id,'event_time':float(timestamp),'kind':kind,'subject':str(subject),'details':details}
    def failure(self,kind,ip,timestamp,event_id,rule=None,user=None):
        if kind!='ssh':return
        ip=safe_ip(ip,self.c)
        if not ip or not isinstance(timestamp,(int,float)) or abs(time.time()-timestamp)>60:return
        event=self.normalize('ssh_failure',ip,{'ip':ip,'user':user,'rule':str(rule)[:100] if rule else None},'ssh:'+event_id,timestamp)
        if self.remember(event):self.create_or_append('ssh_threshold',ip,event)
    def ssh_success(self,ip,user,timestamp,event_id,pid=None):
        ip=safe_ip(ip,self.c)
        if not ip:return
        event=self.normalize('ssh_success',ip,{'ip':ip,'user':user,'sshd_pid':pid},'sshsuccess:'+event_id,timestamp)
        if self.remember(event):self.create_or_append('ssh_threshold',ip,event)
    def session_record(self,kind,fields,content,event_id,timestamp):
        payload=content.split('msg=',1)[-1]
        if fields.get('uid')!='0' or not re.search(r'\bexe="/usr/sbin/(?:sshd|sshd-session)"',payload) or not re.search(r'\bres=success\b',payload):return
        account=re.search(r'\bacct="([a-z_][a-z0-9_-]{0,31})"',payload);address=re.search(r'\baddr=([0-9a-fA-F:.]+)(?:\s|\x27)',payload)
        if not account or not address:return
        try:
            uid=int(fields['auid']);session=int(fields['ses']);pid=int(fields['pid']);ip=str(ipaddress.ip_address(address[1]));user=account[1]
            if uid<1000 or uid==65534 or session<0 or session>=4294967295 or pwd.getpwnam(user).pw_uid!=uid:return
        except (ValueError,KeyError):return
        identity=f'{self.boot_id}:{session}:{uid}'
        if kind in ('USER_END','1106'):
            self.db.execute('UPDATE ssh_sessions SET active=0 WHERE identity=?',(identity,));self.db.commit();return
        snap=process_snapshot(pid)
        details={'boot_id':self.boot_id,'session':str(session),'auid':str(uid),'user':user,'ip':ip,'sshd_pid':pid,'sshd_start_ticks':snap.get('start_ticks') if snap else None,'identity':identity}
        event=self.normalize('ssh_session_open',identity,details,event_id+':session',timestamp)
        if not self.remember(event):return
        self.db.execute('INSERT OR REPLACE INTO ssh_sessions VALUES (?,?,?,?,1)',(identity,event['event_id'],timestamp,canonical(details)));self.db.commit()
        self.store.observe('auditd','ssh_session_open',user,'SSH source linked to audit session '+str(session)+'.',event['event_id'],timestamp)
        self.enrich_ssh_accounts()
    def reconcile_sessions(self,now):
        if now-self.last_session_reconcile<5:return
        self.last_session_reconcile=now
        for identity,stamp,raw in self.db.execute('SELECT identity,event_time,details_json FROM ssh_sessions WHERE active=1 ORDER BY event_time DESC LIMIT 1000').fetchall():
            d=json.loads(raw)
            if d.get('boot_id')!=self.boot_id:
                self.db.execute('UPDATE ssh_sessions SET active=0 WHERE identity=?',(identity,));continue
            if d.get('sshd_start_ticks') is None or now-stamp<2:continue
            snap=process_snapshot(d['sshd_pid'])
            if not snap or snap['start_ticks']!=d['sshd_start_ticks']:self.db.execute('UPDATE ssh_sessions SET active=0 WHERE identity=?',(identity,))
        self.db.commit()
    def session_chain(self,account):
        d=account['details']
        if d.get('boot_id')!=self.boot_id:return []
        identity=f"{d.get('boot_id')}:{d.get('session')}:{d.get('auid')}"
        row=self.db.execute('SELECT event_id,event_time,details_json,active FROM ssh_sessions WHERE identity=?',(identity,)).fetchone()
        # Closed SSH sessions remain historical attribution evidence. The executor
        # verifies exact boot/session/loginuid and safely handles already-closed sessions.
        if not row or row[1]>account['event_time']:return []
        login=self.normalize('ssh_session_open',identity,json.loads(row[2]),row[0],row[1]);ld=login['details']
        producer=self.recent_exec(d.get('pid'),account['event_time'])
        if not producer:return []
        pd=producer['details']
        if any(pd.get(k)!=d.get(k) for k in ('boot_id','session','auid')) or pd.get('uid')!='0' or pathlib.PurePath(pd.get('exe','')).name not in ('useradd','adduser'):return []
        failures=[]
        for r in self.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind='ssh_failure' AND subject=? AND event_time BETWEEN ? AND ? ORDER BY event_time",(ld['ip'],login['event_time']-self.c.get('ssh_compromise_window',300),login['event_time'])):
            e=dict(event_id=r[0],event_time=r[1],kind=r[2],subject=r[3],details=json.loads(r[4]))
            if e['details'].get('user')==ld['user']:failures.append(e)
        return [*failures[-32:],login,producer,account]
    def enrich_ssh_accounts(self):
        for r in self.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind='account_created' AND event_time>?",(time.time()-60,)).fetchall():
            self.correlate_ssh_account(dict(event_id=r[0],event_time=r[1],kind=r[2],subject=r[3],details=json.loads(r[4])))
    def correlate_ssh_account(self,account):
        chain=self.session_chain(account)
        if chain:
            login=next(e for e in chain if e['kind']=='ssh_session_open')
            # Separate each created account: a later account must not replace the
            # containment target of an earlier change in the same SSH session.
            self.create_or_append('ssh_session_account',login['subject']+':'+account['event_id'],account,chain[:-1])
    def audit_line(self,line):
        match=re.match(r'^(?:node=\S+ )?type=(\w+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)',line)
        if not match:return
        kind,stamp,serial,content=match.groups();timestamp=float(stamp)
        if abs(time.time()-timestamp)>60:return
        if self.c.get('persistence_enabled',False):
            from persistence import audit
            audit(self,kind,stamp,serial,content)
        event_id=self.boot_id+':'+stamp+':'+serial
        header=content.split('msg=',1)[0]
        fields=dict(re.findall(r'(\w+)=("[^"]*"|\S+)',header));fields={k:v.strip('"') for k,v in fields.items()}
        if kind in ('USER_START','1105','USER_END','1106'):
            self.session_record(kind,fields,content,event_id,timestamp)
        elif kind in ('SYSCALL','1300'):
            if fields.get('success')!='yes' or fields.get('key') not in self.c.get('audit_exec_keys',['lab_root_exec','aegis_app_exec']):return
            try:pid=int(fields['pid']);ppid=int(fields['ppid'])
            except (KeyError,ValueError):return
            snap=process_snapshot(pid);parent=process_snapshot(ppid)
            # Only kernel audit metadata and process identity enter model evidence.
            details={'pid':pid,'ppid':ppid,'exe':fields.get('exe','')[:200],'boot_id':self.boot_id,'uid':fields.get('uid'),'auid':fields.get('auid'),'session':fields.get('ses'),'start_ticks':snap.get('start_ticks') if snap else None,'parent_start_ticks':parent.get('start_ticks') if parent else None,'cgroup':snap.get('cgroup') if snap else parent.get('cgroup') if parent else None}
            event=self.normalize('process_exec',str(pid),details,event_id+':exec',timestamp)
            if self.remember(event):
                self.store.observe('auditd','process_exec',details['exe'],'Process execution; PID '+str(pid)+', parent '+str(ppid)+'.',event['event_id'],timestamp)
                self.enrich_accounts(event);self.enrich_ssh_accounts()
                if pathlib.PurePath(details['exe']).name in ('sh','dash','bash') and any(unit in line.rsplit(':',1)[-1].split('/') for unit in self.c.get('application_units',[]) for line in (details.get('cgroup') or '').splitlines()):
                    self.create_or_append('application_shell',event['event_id'],event)
        elif kind in ('ADD_USER','1114'):
            if fields.get('uid')!='0':return
            payload=content.split('msg=',1)[-1]
            if not re.search(r'\bres=success\b',payload):return
            account=re.search(r'\bacct="?([a-z_][a-z0-9_-]{0,31})"?(?:\s|\x27|$)',payload);name=account[1] if account else None
            numeric_target=re.search(r'\bop=adding user id=(\d+)(?:\s|\x27|$)',payload)
            if name is None and numeric_target is None:return
            try:pid=int(fields['pid'])
            except (ValueError,KeyError):return
            details={'requested_name':name,'target_uid':int(numeric_target[1]) if numeric_target else None,'pid':pid,'producer_uid':0,'auid':fields.get('auid'),'session':fields.get('ses'),'boot_id':self.boot_id}
            pending_id=event_id+':account'
            self.db.execute('INSERT OR IGNORE INTO pending_account_resolution VALUES (?,?,?,?)',(pending_id,timestamp,canonical(details),time.time()+5));self.db.commit()
            self.resolve_account(pending_id,timestamp,details)
        # EXECVE/PROCTITLE/PATH are deliberately not persisted: arguments may contain secrets.
    def resolve_account(self,event_id,timestamp,details):
        name=details.get('requested_name');target_uid=details.get('target_uid')
        try:
            if name is None:name=pwd.getpwuid(target_uid).pw_name
            account_uid=pwd.getpwnam(name).pw_uid
        except (KeyError,TypeError):return False
        if target_uid is not None and account_uid!=target_uid:return False
        event=self.normalize('account_created',name,{k:v for k,v in details.items() if k not in ('requested_name','target_uid')},event_id,timestamp)
        event['details']['account_uid']=account_uid
        if self.remember(event):
            self.store.observe('auditd','account_created',name,'Account created; awaiting correlation and assessment before response.',event_id,timestamp)
            self.correlate_ssh_account(event) if self.session_chain(event) else self.create_or_append('web_shell_account',name,event,self.lineage(event))
        self.db.execute('DELETE FROM pending_account_resolution WHERE event_id=?',(event_id,));self.db.commit();return True
    def resolve_pending(self,now):
        for event_id,timestamp,details,deadline in self.db.execute('SELECT * FROM pending_account_resolution LIMIT 256').fetchall():
            if self.resolve_account(event_id,timestamp,json.loads(details)):continue
            if now>deadline:
                self.store.observe('auditd','account_resolution_failed',str(json.loads(details).get('target_uid')),'Account event retained; UID resolution timed out. No response executed.',event_id,timestamp)
                self.store.state('last_unresolved_account',{'event_id':event_id,'time':timestamp,'details':json.loads(details)})
                self.db.execute('DELETE FROM pending_account_resolution WHERE event_id=?',(event_id,));self.db.commit()
    def account(self,line):self.audit_line(line)
    def recent_exec(self,pid,timestamp):
        rows=self.db.execute("SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind='process_exec' AND subject=? AND event_time BETWEEN ? AND ? ORDER BY event_time DESC LIMIT 1",(str(pid),timestamp-15,timestamp+.01)).fetchone()
        if not rows:return None
        return dict(event_id=rows[0],event_time=rows[1],kind=rows[2],subject=rows[3],details=json.loads(rows[4]))
    def lineage(self,account):
        d=account['details'];producer=self.recent_exec(d['pid'],account['event_time'])
        if not producer:return []
        p=producer['details']
        if p.get('boot_id')!=d.get('boot_id') or p.get('auid')!=d.get('auid') or p.get('session')!=d.get('session') or pathlib.PurePath(p.get('exe','')).name not in ('useradd','adduser'):return []
        chain=[producer];current=producer
        for _ in range(8):
            cd=current['details'];parent=self.recent_exec(cd.get('ppid'),current['event_time'])
            if not parent:break
            pd=parent['details']
            if pd.get('boot_id')!=cd.get('boot_id'):break
            # Snapshot parent start time must match recorded parent identity. No time-only edge.
            if cd.get('parent_start_ticks') is None or pd.get('start_ticks')!=cd['parent_start_ticks']:break
            chain.insert(0,parent)
            unit=next((u for u in self.c.get('web_units',['defense-lab-gateway.service','defense-lab-workload.service']) if any(u in line.strip().rsplit(':',1)[-1].split('/') for line in (pd.get('cgroup') or '').splitlines())),None)
            if pathlib.PurePath(pd.get('exe','')).name in ('sh','dash','bash') and unit:
                app=self.recent_exec(pd.get('ppid'),parent['event_time'])
                if app:
                    ad=app['details']
                    same_unit=any(unit in line.strip().rsplit(':',1)[-1].split('/') for line in (ad.get('cgroup') or '').splitlines())
                    if ad.get('boot_id')==pd.get('boot_id') and pd.get('parent_start_ticks') is not None and ad.get('start_ticks')==pd['parent_start_ticks'] and same_unit:
                        chain.insert(0,app)
                return chain
            current=parent
        return []
    def enrich_accounts(self,event):
        rows=self.db.execute("SELECT id FROM cases WHERE kind='web_shell_account' AND status NOT IN ('defended','recognized') AND created_at>?",(time.time()-60,)).fetchall()
        for row in rows:
            for account in self.events(row[0]):
                if account['kind']=='account_created':
                    lineage=self.lineage(account)
                    if lineage:self.create_or_append('web_shell_account',account['subject'],account,lineage)
    def snapshot(self,identifier,kind,subject,version):
        events=self.events(identifier);allowed=[];required=[];edges=[]
        if kind=='app_sql_persistence':
            from persistence import plan
            allowed,required,edges=plan(events,self.c,self.boot_id)
        elif kind=='app_sql_account':
            from app_correlation import plan
            allowed,required,edges=plan(events,self.c,self.boot_id)
        elif kind=='ssh_threshold':
            # Failures, signatures, or a later login alone cannot justify containment.
            # IP response requires a trusted session->behavior link, not implemented
            # by these aggregate collectors. Keep evidence, offer no IP action.
            pass
        elif kind=='ssh_session_account':
            account=next((e for e in reversed(events) if e['kind']=='account_created'),None)
            chain=self.session_chain(account) if account else []
            login=next((e for e in chain if e['kind']=='ssh_session_open'),None)
            recorded={e['event_id'] for e in events}
            if login and all(e['event_id'] in recorded for e in chain):
                ld=login['details'];actor=ld['user'];failures=[e for e in chain if e['kind']=='ssh_failure']
                producer=next(e for e in chain if e['kind']=='process_exec')
                edges=[{'from':login['event_id'],'to':producer['event_id'],'relation':'same_boot_audit_session_and_loginuid'}, {'from':producer['event_id'],'to':account['event_id'],'relation':'same_boot_producer_pid_auid_session'}]
                edges.extend({'from':e['event_id'],'to':login['event_id'],'relation':'same_source_and_account_prior_failure_not_causal'} for e in failures)
                try:uid=pwd.getpwnam(account['subject']).pw_uid;actor_uid=pwd.getpwnam(actor).pw_uid
                except KeyError:uid=actor_uid=0
                scoped=ssh_response_user(actor,self.c) and actor not in self.c['protected_users'] and actor not in self.c.get('ssh_account_creator_allowlist',[]) and actor_uid==int(ld['auid'])
                target_ok=bool(re.fullmatch(r'lab_[a-z0-9_]{1,24}',account['subject'])) and account['subject'] not in self.c['protected_users'] and uid>=1000 and uid!=65534 and uid==account['details'].get('account_uid')
                if scoped and target_ok:
                    allowed=[dict(action='quarantine_account',user=account['subject']),dict(action='terminate_session',boot_id=ld['boot_id'],session=int(ld['session']),auid=actor_uid,user=actor)]
                    # Blocking a shared source is never inferred from the model verdict.
                    if len(failures)>=self.c['ssh_threshold'] and ld['ip'] in self.c.get('ssh_dedicated_source_ips',[]) and safe_ip(ld['ip'],self.c):allowed.append(dict(action='block_ip',ip=ld['ip']))
                    required=[e['event_id'] for e in chain]
        elif kind=='web_shell_account':
            account=next((e for e in reversed(events) if e['kind']=='account_created'),None)
            if account:
                chain=self.lineage(account);recorded={e['event_id'] for e in events}
                if chain and all(e['event_id'] in recorded for e in chain) and re.fullmatch(r'lab_[a-z0-9_]{1,24}',subject) and subject not in self.c['protected_users']:
                    try:uid=pwd.getpwnam(subject).pw_uid
                    except KeyError:uid=0
                    if uid>=1000 and uid!=65534 and account['details'].get('account_uid')==uid:
                        allowed=[dict(action='quarantine_account',user=subject)];required=[e['event_id'] for e in chain]+[account['event_id']]
                        for parent,child in zip(chain,chain[1:]):edges.append({'from':parent['event_id'],'to':child['event_id'],'relation':'kernel_ppid_and_matching_parent_start_ticks'})
                        edges.append({'from':chain[-1]['event_id'],'to':account['event_id'],'relation':'same_boot_producer_pid_auid_session'})
        actor=next((e['details']['user'] for e in events if e['kind']=='ssh_session_open'),None);authorization='not_established'
        account=next((e for e in reversed(events) if e['kind']=='account_created'),None)
        if kind=='persistence_change':
            try:actor=pwd.getpwuid(int(events[-1]['details'].get('auid'))).pw_name
            except (KeyError,ValueError,TypeError):pass
            if actor in self.c.get('ssh_account_creator_allowlist',[]):authorization='approved'
        if account:
            try:
                if actor is None:actor=pwd.getpwuid(int(account['details'].get('auid'))).pw_name
            except (KeyError,ValueError,TypeError):pass
            if actor in self.c.get('ssh_account_creator_allowlist',[]) and not allowed:authorization='approved'
            elif actor and actor not in self.c.get('ssh_account_creator_allowlist',[]):authorization='unapproved'
        return {'version':version,'events':events,'edges':edges,'allowed_actions':allowed,'required_evidence_ids':required,'policy':{'mode':'correlated','minimum_confidence':.85,'account_scope':'lab_ only; audited SSH policy, web shell lineage, or broker SQL session plus kernel account audit required','model_cannot_authorize_new_actions':True,'ip_scope':'confirmed_session_compromise_and_explicit_dedicated_source_only','ssh_response_users':self.c.get('ssh_response_users',[]),'ssh_lab_users_enabled':self.c.get('ssh_lab_users_enabled',False),'account_creator_allowlist':self.c.get('ssh_account_creator_allowlist',[]),'actor':actor,'actor_authorization':authorization,'session_rule':'audited SSH session + root useradd + unapproved lab account creation; prior failures additionally required for dedicated IP block'}}
    def validate_result(self,row,result):
        identifier,version,evidence=row;data=json.loads(evidence)
        if not isinstance(result,dict) or result.get('case_id')!=identifier or type(result.get('version')) is not int or result['version']!=version or result.get('snapshot_hash')!=hashlib.sha256(evidence.encode()).hexdigest():raise ValueError('stale version or snapshot hash')
        completed=result.get('completed_at')
        if not isinstance(completed,(float,int)) or isinstance(completed,bool) or not -5<=time.time()-completed<=30 or result.get('status')!='complete':raise ValueError('expired/incomplete analysis')
        analysis=result.get('analysis')
        if not isinstance(analysis,dict) or not isinstance(analysis.get('summary'),str) or not analysis['summary'].strip() or len(analysis['summary'])>12000:raise ValueError('missing summary')
        if data.get('policy',{}).get('actor_authorization')=='approved' and analysis.get('attack') is True:raise ValueError('assessment contradicts approved account creator')
        if type(analysis.get('attack')) is not bool or type(analysis.get('confidence')) not in (int,float) or not 0<=analysis['confidence']<=1 or not isinstance(analysis.get('uncertainty'),str):raise ValueError('invalid assessment')
        references=analysis.get('evidence_ids');actions=analysis.get('proposed_actions')
        ids={e['event_id'] for e in data['events']}
        if not isinstance(references,list) or not all(isinstance(x,str) and x in ids for x in references) or not isinstance(actions,list) or len(actions)>8:raise ValueError('invalid evidence references')
        if any(not isinstance(action,dict) or action not in data['allowed_actions'] for action in actions):raise ValueError('proposal outside root policy')
        if len({canonical(action) for action in actions})!=len(actions):raise ValueError('duplicate action')
        if actions and not set(data['required_evidence_ids']).issubset(references):raise ValueError('missing causal/threshold evidence')
        return analysis
    def apply_analysis(self,identifier,version,evidence,result):
        current=self.db.execute('SELECT version,status,evidence_json,kind,subject FROM cases WHERE id=?',(identifier,)).fetchone()
        if not current or current[0]!=version or current[1]!='awaiting_analysis' or current[2]!=evidence:return
        try:analysis=self.validate_result((identifier,version,evidence),result)
        except (ValueError,TypeError,KeyError) as e:self.status(identifier,'analysis_error',{'error':str(e)});return
        analysis['origin']=str(result.get('model','unknown'))[:100]
        # Durable description and recognized stage MUST precede any execution.
        self.db.execute('UPDATE cases SET analysis_json=? WHERE id=?',(canonical(analysis),identifier));self.status(identifier,'recognized',{'version':version})
        data=json.loads(evidence);fresh=self.snapshot(identifier,current[3],current[4],version)
        if not data['allowed_actions']:self.status(identifier,'authorized' if data.get('policy',{}).get('actor_authorization')=='approved' else 'insufficient_evidence');return
        if not analysis['attack'] or analysis['confidence']<.85 or not analysis['proposed_actions']:self.status(identifier,'observing');return
        if fresh['allowed_actions']!=data['allowed_actions'] or fresh['required_evidence_ids']!=data['required_evidence_ids']:self.status(identifier,'analysis_error',{'error':'root prerequisites changed'});return
        results=[]
        for action in analysis['proposed_actions']:
            try:
                started=time.monotonic();out=self.execute(action)
                if not isinstance(out,dict) or out.get('verified') is not True:raise RuntimeError('executor did not verify action')
                if action['action']=='terminate_session':
                    self.db.execute('UPDATE ssh_sessions SET active=0 WHERE identity=?',(f"{action['boot_id']}:{action['session']}:{action['auid']}",))
                out.update(executed_at=time.time(),execution_ms=round((time.monotonic()-started)*1000,3));out['reaction_ms']=round((out['executed_at']-max(e['event_time'] for e in data['events']))*1000,3);results.append({'action':action,'status':'executed','result':out})
            except Exception as e:results.append({'action':action,'status':'failed','error':str(e)[:500]})
        self.db.execute('UPDATE cases SET result_json=? WHERE id=?',(canonical(results),identifier));self.status(identifier,'defended' if all(x['status']=='executed' for x in results) else 'defense_error')
    def tick(self,now=None):
        now=time.time() if now is None else now
        self.reconcile_sessions(now)
        self.resolve_pending(now)
        for identifier,created,updated,kind,subject,version in self.db.execute("SELECT id,created_at,updated_at,kind,subject,version FROM cases WHERE status='collecting'").fetchall():
            if now-updated>=self.c.get('correlation_quiet_seconds',2) or now-created>=self.c.get('correlation_max_seconds',5):
                evidence=canonical(self.snapshot(identifier,kind,subject,version));self.db.execute('UPDATE cases SET evidence_json=? WHERE id=?',(evidence,identifier));self.status(identifier,'awaiting_analysis',{'version':version,'snapshot_hash':hashlib.sha256(evidence.encode()).hexdigest()})
        for identifier,version,evidence,updated in self.db.execute("SELECT id,version,evidence_json,updated_at FROM cases WHERE status='awaiting_analysis'").fetchall():
            path=pathlib.Path(self.c.get('ai_results_dir','/var/lib/defense-agent-ai'))/f'{identifier}-v{version}.json'
            try:
                fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(fd,'r') as f:
                    info=os.fstat(f.fileno())
                    try:expected_uid=pwd.getpwnam('defense-ai').pw_uid
                    except KeyError:expected_uid=os.getuid()
                    if not stat.S_ISREG(info.st_mode) or info.st_size>131072 or info.st_uid not in (0,expected_uid) or info.st_mode & 0o022:raise ValueError('invalid result file')
                    result=json.load(f)
                self.apply_analysis(identifier,version,evidence,result)
            except FileNotFoundError:
                if now-updated>self.c.get('analysis_timeout_seconds',45):self.status(identifier,'analysis_error',{'error':'model analysis timeout; no defense performed'})
            except (OSError,ValueError,TypeError) as e:self.status(identifier,'analysis_error',{'error':str(e)[:300]})
        if now-self.last_cleanup>30:
            self.last_cleanup=now;self.db.execute('DELETE FROM correlation_events WHERE event_time<?',(now-600,));self.db.execute('DELETE FROM ssh_sessions WHERE event_time<?',(now-86400,));self.db.execute('DELETE FROM correlation_events WHERE rowid NOT IN (SELECT rowid FROM correlation_events ORDER BY event_time DESC LIMIT 20000)');self.db.commit()

def credential_socket(path,typ):
    try:os.unlink(path)
    except FileNotFoundError:pass
    s=socket.socket(socket.AF_UNIX,typ);s.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);s.bind(path);os.chmod(path,0o600);return s

def receive(s):
    data,ancillary,flags,address=s.recvmsg(65536,socket.CMSG_SPACE(struct.calcsize('3i')))
    uid=None
    for level,kind,value in ancillary:
        if level==socket.SOL_SOCKET and kind==socket.SCM_CREDENTIALS: uid=struct.unpack('3i',value)[1]
    if uid!=0 or flags & socket.MSG_TRUNC:raise ValueError('untrusted or truncated message')
    return data

def serve_executor(c):
    executor=Executor(c);executor.firewall_init();s=credential_socket(c['executor_socket'],socket.SOCK_SEQPACKET);s.listen(8)
    while True:
        client,_=s.accept()
        with client:
            client.settimeout(3)
            try:result=executor.execute(json.loads(receive(client)));reply={'ok':True,'result':result}
            except Exception as e:reply={'ok':False,'error':str(e)[:500]}
            client.send(json.dumps(reply).encode())

def request_executor(c,request):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(30);s.connect(c['executor_socket']);s.send(json.dumps(request).encode());reply=json.loads(s.recv(65536))
    if not reply['ok']:raise RuntimeError(reply['error'])
    return reply['result']

def audit_plugin():
    import sys
    s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
    for line in sys.stdin:
        if re.search(r'^(?:node=\S+ )?type=(?:ADD_USER|1114|SYSCALL|1300|PATH|1302|EOE|1320|USER_LOGIN|1112|USER_START|1105|USER_END|1106)\s',line):
            if re.search(r'type=(?:SYSCALL|1300)\s',line) and not re.search(r'\bkey="?(?:lab_root_exec|aegis_app_exec|aegis_persistence)"?(?:\s|$)',line):continue
            try:s.sendto(line.encode()[:60000],DEFAULTS['audit_socket'])
            except OSError as e:print(f'defense-agent audit delivery failed: {e}',file=sys.stderr,flush=True)

def journal_reader(queue):
    # journal metadata is trusted, MESSAGE content alone is never sufficient.
    while True:
        p=subprocess.Popen(['journalctl','-f','-n','0','-o','json','_COMM=sshd','_COMM=sshd-session'],stdout=subprocess.PIPE,text=True)
        JOURNAL_HEALTH['connected']=True
        for line in p.stdout:
            JOURNAL_HEALTH['last_received_at']=time.time()
            try:queue.put(('ssh',json.loads(line)),timeout=1)
            except Exception:JOURNAL_HEALTH['dropped_events']+=1
        JOURNAL_HEALTH['connected']=False
        time.sleep(1)

def serve_core(c):
    import queue
    if c.get('mode','correlated')!='correlated':raise ValueError('Only correlated analyze-before-defense mode is permitted')
    store=Store(c);engine=CorrelatedEngine(c,store,lambda r:request_executor(c,r));s=credential_socket(c['audit_socket'],socket.SOCK_DGRAM);s.settimeout(.05)
    events=queue.Queue(maxsize=4096);threading.Thread(target=journal_reader,args=(events,),daemon=True).start()
    last_health=0;last_audit_health=0;audit_health={}
    while True:
        try:engine.account(receive(s).decode(errors='replace'))
        except socket.timeout:pass
        except Exception as e:print('audit input rejected:',e,flush=True)
        for _ in range(100):
            try:kind,event=events.get_nowait()
            except queue.Empty:break
            if kind=='health':store.state('journal_health',{'time':time.time(),'error':event});continue
            if event.get('_COMM') not in ('sshd','sshd-session') or str(event.get('_UID'))!='0':continue
            message=event.get('MESSAGE','')
            m=re.search(r'^Failed (?:password|publickey) for (?:invalid user )?\S+ from ([0-9a-fA-F:.]+) port \d+',message)
            if not m:m=re.search(r'^Invalid user \S+ from ([0-9a-fA-F:.]+) port \d+',message)
            event_id=event.get('__CURSOR',str(event['__REALTIME_TIMESTAMP']))
            timestamp=int(event['__REALTIME_TIMESTAMP'])/1e6
            accepted=re.search(r'^Accepted (?:publickey|password) for (\S+) from ([0-9a-fA-F:.]+) port \d+',message)
            if m:store.observe('sshd','ssh_auth_failure',m[1],'Authentication failed / unknown account.',event_id,timestamp)
            elif accepted:store.observe('sshd','ssh_login_success',accepted[2],'Successful sign-in for account '+accepted[1][:50]+'.',event_id,timestamp)
            else:store.observe('sshd','ssh_activity','sshd','SSH connection or session event.',event_id,timestamp)
            if m:
                user_match=re.search(r'^(?:Failed (?:password|publickey) for (?:invalid user )?|Invalid user )(\S+)',message)
                engine.failure('ssh',m[1],timestamp,event_id,user=user_match[1] if user_match else None)
            elif accepted:engine.ssh_success(accepted[2],accepted[1],timestamp,event_id,event.get('_PID'))
        store.db.commit()
        if c.get('application_enabled',False):
            try:
                from app_correlation import ingest
                ingest(engine)
            except Exception as e:store.state('app_sensor_error',{'time':time.time(),'error':str(e)[:150]})
        engine.tick()
        if time.time()-last_health>5:
            last_health=time.time();store.state('heartbeat',{'time':last_health,'pid':os.getpid()})
            if last_health-last_audit_health>30:
                last_audit_health=last_health
                try:
                    status=run(['auditctl','-s']);audit_health={x.split()[0]:' '.join(x.split()[1:]) for x in status.splitlines() if x.split()}
                except Exception as e:audit_health={'error':str(e)[:200]}
            health={'time':last_health,'pid':os.getpid(),'journal':dict(JOURNAL_HEALTH),'audit':audit_health}
            store.state('sensor_health',health)
            pathlib.Path(c['data_dir'],'health.json').write_text(json.dumps(health))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['core','executor','audit-plugin']);parser.add_argument('--config',default='/etc/defense-agent/config.json');a=parser.parse_args()
    if a.mode=='audit-plugin':audit_plugin()
    else:
        c=DEFAULTS.copy();c.update(json.loads(pathlib.Path(a.config).read_text()));pathlib.Path(c['runtime_dir']).mkdir(mode=0o700,parents=True,exist_ok=True)
        (serve_core if a.mode=='core' else serve_executor)(c)
