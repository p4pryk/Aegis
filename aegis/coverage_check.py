"""Bounded metadata-only coverage inventory. Never enables sources or reads log contents."""
import os,pathlib,re,stat,subprocess,threading,time

CATALOG=(
 ('Nginx',('nginx.service',),('/var/log/nginx/access.log','/var/log/nginx/error.log'),'Access logs can use the access adapter; error logs need a supported structured export.'),
 ('Apache',('apache2.service','httpd.service'),('/var/log/apache2/access.log','/var/log/httpd/access_log'),'Configure access files explicitly; custom virtual-host paths are not discovered.'),
 ('PostgreSQL',('postgresql.service',),('/var/log/postgresql',),'Native database audit/query logs need a supported JSONL export; service logs alone do not cover database activity.'),
 ('MySQL / MariaDB',('mysql.service','mysqld.service','mariadb.service'),('/var/log/mysql/error.log','/var/log/mysqld.log'),'Native database audit/query logs need a supported JSONL export; error logs do not prove query coverage.'),
 ('Redis',('redis.service','redis-server.service'),('/var/log/redis/redis-server.log',),'Native Redis logs need a supported JSONL export; command auditing is not inferred.'),
 ('Container runtime',('docker.service','containerd.service','podman.service'),(), 'Container stdout, application audit and runtime events need explicit adapters/exports; host logs do not cover every container.'),
)
GAPS={'GAP','LAGGING','STALE','NEEDS CONFIG','PARTIAL','MISSING','UNSAFE','FORMAT REVIEW','DOWN','DISABLED','UNKNOWN','RULES MISSING'}

def command(args):
    try:
        result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=3)
        return result.stdout if result.returncode==0 and len(result.stdout)<=65536 else None
    except (OSError,subprocess.TimeoutExpired):return None

def metadata(path):
    try:
        info=os.lstat(path)
        return dict(kind='file' if stat.S_ISREG(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'unsafe',uid=info.st_uid,mode=info.st_mode)
    except FileNotFoundError:return {'kind':'missing'}
    except OSError:return {'kind':'unknown'}

def inventory():
    units=tuple(dict.fromkeys(u for _,names,_,_ in CATALOG for u in names))
    raw=command(['systemctl','show','--no-pager','--property=Id,LoadState,ActiveState',*units])
    services={}
    if raw is not None:
        for block in raw.strip().split('\n\n'):
            fields=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
            if fields.get('Id') in units:services[fields['Id']]=fields
    rules=command(['auditctl','-l'])
    keys=None if rules is None else sorted(set(re.findall(r'(?:-k\s+|key=)"?([A-Za-z0-9_-]+)',rules)))
    return dict(services=services,services_available=raw is not None and bool(services),rules=keys)

def assess(config,health,facts,inspect=metadata,now=None):
    now=time.time() if now is None else now;rows=[]
    sources={s['name']:s for s in health.get('sources',[])}
    def add(name,status,evidence,next_step):rows.append(dict(name=name,status=status,evidence=evidence,next_step=next_step))
    for name in ('Kernel audit','SSH journal','Service journal'):
        source=sources.get(name,{})
        status=source.get('status','UNKNOWN')
        # File-mode SSH collection is checked separately below; a disabled journal is expected.
        if name=='SSH journal' and health.get('system_log_coverage',{}).get('mode')=='files':continue
        add(name+' collector','READY' if status in ('LIVE','QUIET') else status,source.get('reason','Collector health unavailable'),'Liveness covers selected streams only; it does not prove parser or application completeness.')
    system=health.get('system_log_coverage',{})
    if not system.get('enabled',True):add('System security parsers','DISABLED','system_logs_enabled is false','Enable supported system sources after reviewing the configuration.')
    if system.get('mode')=='files':
        for category,path in system.get('paths',{}).items():
            source=next((s for s in sources.values() if s.get('path')==path),{})
            add(category+' system file',source.get('status','UNKNOWN'),path,source.get('reason','Check that this selected source is readable and emits supported records.'))
    required=['lab_root_exec','aegis_identity']+(['aegis_persistence'] if config.get('persistence_enabled',False) else [])
    keys=facts.get('rules')
    missing=[key for key in required if keys is not None and key not in keys]
    add('Selected audit rules','UNKNOWN' if keys is None else 'RULES MISSING' if missing else 'KEYS PRESENT',
        'Audit rules could not be inspected' if keys is None else 'Missing keys: '+', '.join(missing) if missing else ', '.join(required),
        'Verify the actual rule filters and watched paths; key presence alone does not establish full syscall/file coverage.')
    configured=[]
    for item in config.get('application_sources',[])[:8]:
        path=item['path'];info=inspect(path);source=sources.get('App '+item['name'],{})
        kind=info['kind'];status='CONFIGURED'
        if kind=='missing':status='MISSING'
        elif kind=='unknown':status='UNKNOWN'
        elif kind!='file' or info.get('uid')!=item.get('owner_uid',0) or info.get('mode',0)&0o022:status='UNSAFE'
        elif source.get('status') in ('DOWN','MISSING','GAP','LAGGING'):status='FORMAT REVIEW' if source.get('invalid') or source.get('unrecognized') else source['status']
        elif source.get('invalid') or source.get('unrecognized'):status='FORMAT REVIEW'
        elif source.get('parsed',0)>0:status='OBSERVED'
        configured.append((path,status))
        add('App '+item['name'],status,path+' / '+item['format'],
            'Selected records parsed in this collector session; other events may still be absent.' if status=='OBSERVED' else 'Check owner, permissions, parser mapping and producer output. A quiet file is not proof that all security events are logged.')
    for label,units,paths,note in CATALOG:
        detected=[u+':'+facts['services'][u].get('ActiveState','unknown') for u in units if facts.get('services',{}).get(u,{}).get('LoadState')=='loaded']
        found=[(p,inspect(p)) for p in paths]
        present=[(p,i) for p,i in found if i['kind']!='missing']
        if not detected and not present:continue
        linked=[(p,state) for p,state in configured if any(p==hint or (info['kind']=='directory' and pathlib.PurePosixPath(hint) in pathlib.PurePosixPath(p).parents) for hint,info in present)]
        # A matching file cannot prove coverage of all virtual hosts, databases or containers.
        add(label,'UNKNOWN' if not detected and present and all(i['kind']=='unknown' for _,i in present) else 'PARTIAL' if linked else 'NEEDS CONFIG',', '.join(detected+[p for p,_ in present]),note+(' Explicit adapters: '+', '.join(p for p,_ in linked)+'.' if linked else ' No matching explicit file adapter found.'))
    if not facts.get('services_available'):add('Service discovery','UNKNOWN','systemctl inventory unavailable','Inspect custom services manually; missing inventory must not be treated as complete coverage.')
    return dict(time=now,rows=rows,gaps=sum(r['status'] in GAPS for r in rows),
                scope='Fixed service/path hints and up to eight configured application files; no log contents, config contents, directory scans or automatic enrollment. Custom paths, containers and unknown applications require manual review.')

class Probe:
    """One background probe at most; slow discovery never blocks collection."""
    def __init__(self,config):self.config=config;self.result={};self.thread=None;self.started=None
    def poll(self,health,now):
        if (self.thread is None or not self.thread.is_alive()) and (self.started is None or now-self.started>=60):
            self.started=now
            def work():
                try:self.result=assess(self.config,health,inventory())
                except Exception:self.result=dict(time=time.time(),rows=[],gaps=1,error='Coverage inventory failed')
            self.thread=threading.Thread(target=work,daemon=True);self.thread.start()
        return self.result

def lines(report,width,now,core_fresh=True):
    from console import wrapped
    out=[]
    def add(text,level='neutral'):out.extend(wrapped(text,width,level))
    add('COVERAGE CHECK / METADATA ONLY')
    if not report or not core_fresh or not 0<=now-report.get('time',0)<120:
        add('Coverage inventory unavailable or stale; completeness is unknown.','warning');return out
    if report.get('error'):add(report['error']+'; completeness is unknown.','warning');return out
    add('Review items: '+str(report.get('gaps',0))+' / checked every 60s. No sources are enabled automatically.','warning')
    for row in report.get('rows',[]):
        level='warning' if row['status'] in GAPS else 'neutral'
        add('['+row['status']+'] '+row['name'],level)
        add('  '+row['evidence']);add('  '+row['next_step'],level)
    add(report.get('scope',''),'warning');return out
