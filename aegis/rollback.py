"""Root-only, explicit rollback receipts. No rollback operation is exposed to the model."""
import argparse,contextlib,ctypes,fcntl,hashlib,ipaddress,json,os,pathlib,pwd,re,stat,subprocess,tempfile,time,uuid

SUPPORTED=('block_ip','quarantine_account','quarantine_persistence')

def digest(value):return hashlib.sha256(value if isinstance(value,bytes) else value.encode()).hexdigest()
def boot():return pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':'))

def atomic(path,data,mode=0o600,owner=None):
    fd,name=tempfile.mkstemp(prefix='.aegis-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            os.fchmod(out.fileno(),mode)
            if owner:os.fchown(out.fileno(),*owner)
            out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(name,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(name):os.unlink(name)

def account(name):
    records={};generation={}
    for kind in ('passwd','shadow'):
        path=pathlib.Path('/etc')/kind;info=path.stat();raw=path.read_bytes()
        rows=[line.decode().split(':') for line in raw.splitlines() if line.split(b':',1)[0]==name.encode()]
        if len(rows)!=1:raise ValueError('Local account identity unavailable')
        records[kind]=rows[0];generation[kind]=[info.st_dev,info.st_ino,info.st_mtime_ns,info.st_ctime_ns,digest(raw)]
    p,s=records['passwd'],records['shadow']
    if len(p)!=7 or len(s)!=9 or p[1]!='x':raise ValueError('Unsupported local account format')
    qp=list(p);qp[6]='/usr/sbin/nologin';qs=list(s);qs[1]=s[1] if s[1].startswith('!') else '!'+s[1];qs[7]='1'
    return {'uid':int(p[2]),'shell':p[6],'expiry':s[7],'locked':s[1].startswith('!'),
            'password_empty':not s[1],'passwd_hash':digest(':'.join(p)),'shadow_hash':digest(':'.join(s)),
            'quarantine_passwd_hash':digest(':'.join(qp)),'quarantine_shadow_hash':digest(':'.join(qs)),
            'generation':generation}

def restore_account(name,before,after):
    # Share shadow-utils' password lock across the comparison and both atomic replacements.
    libc=ctypes.CDLL(None)
    if libc.lckpwdf()!=0:raise RuntimeError('Account database busy')
    try:
        if account(name)!=after:raise ValueError('Account/database changed since containment')
        updates=[]
        for kind in ('passwd','shadow'):
            path=pathlib.Path('/etc')/kind;info=path.stat();lines=path.read_text().splitlines()
            for n,line in enumerate(lines):
                fields=line.split(':')
                if fields[0]!=name:continue
                if kind=='passwd':fields[6]=before['shell']
                else:
                    fields[7]=before['expiry']
                    if not before['locked']:
                        if not fields[1].startswith('!'):raise ValueError('Lock changed')
                        fields[1]=fields[1][1:]
                if digest(':'.join(fields))!=before[kind+'_hash']:raise ValueError('Original account state cannot be reconstructed')
                lines[n]=':'.join(fields)
            updates.append((path,('\n'.join(lines)+'\n').encode(),stat.S_IMODE(info.st_mode),(info.st_uid,info.st_gid)))
        # Restore the shell first; expiry/password containment remains until the second write.
        for args in updates:atomic(*args)
        current=account(name)
        if any(current[k]!=before[k] for k in ('uid','shell','expiry','locked','passwd_hash','shadow_hash')):raise RuntimeError('Account restore not verified')
    finally:libc.ulckpwdf()

def file_state(path):
    from persistence import fingerprint
    s=os.lstat(path)
    if not stat.S_ISREG(s.st_mode):raise ValueError('Expected a regular file')
    h,identity=fingerprint(path);s=os.lstat(path)
    return {'sha256':h,'identity':list(identity),'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'ctime_ns':s.st_ctime_ns}

def ip_state(ip):
    # nft 1.0.9 ignores -j for get element; list set has a stable JSON representation.
    version=ipaddress.ip_address(ip).version;family='blocked4' if version==4 else 'blocked6'
    from agent import run
    data=json.loads(run(['nft','-j','list','set','inet','defense_lab',family]))
    sets=[item['set'] for item in data.get('nftables',[]) if 'set' in item]
    if len(sets)!=1:raise ValueError('Firewall set unavailable')
    current=sets[0]
    if current.get('family')!='inet' or current.get('table')!='defense_lab' or current.get('name')!=family or current.get('type')!=('ipv4_addr' if version==4 else 'ipv6_addr') or 'interval' in current.get('flags',[]):
        raise ValueError('Firewall set schema changed')
    for item in current.get('elem',[]):
        if isinstance(item,str) and item==ip:return {'comment':None}
        if isinstance(item,dict):
            element=item.get('elem',item)
            if element.get('val')==ip:return {'comment':element.get('comment')}
    return None

class Journal:
    def __init__(self,config):
        self.config=config;self.root=pathlib.Path(config['data_dir'])/'rollback'
        self.root.mkdir(mode=0o700,exist_ok=True)
        s=self.root.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('Unsafe rollback directory')
    @contextlib.contextmanager
    def lock(self):
        fd=os.open(self.root/'lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as out:
            fcntl.flock(out,fcntl.LOCK_EX);yield
    def path(self,identifier):
        if not re.fullmatch('[a-f0-9]{32}',identifier):raise ValueError('Invalid receipt ID')
        return self.root/(identifier+'.json')
    def read(self,identifier):
        fd=os.open(self.path(identifier),os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        with os.fdopen(fd) as f:
            s=os.fstat(f.fileno())
            if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077 or s.st_size>131072:raise ValueError('Unsafe receipt')
            return json.load(f)
    def save(self,r):atomic(self.path(r['id']),encoded(r).encode())
    def entries(self):return [self.read(p.stem) for p in sorted(self.root.glob('*.json'))]
    def record(self,executor,request):
        with self.lock():
            action=request.get('action');target=request.get('ip') or request.get('user') or request.get('path')
            if action=='block_ip':
                address=ipaddress.ip_address(target);target=str(getattr(address,'ipv4_mapped',None) or address)
            r={'id':uuid.uuid4().hex,'action':action,'target':target,'boot':boot(),'time':time.time(),'state':'prepared','eligible':False,'history':[]}
            try:
                if action=='quarantine_account':r['before']=account(target)
                elif action=='quarantine_persistence':r['before']=file_state(target)
                elif action=='block_ip':r['before']=ip_state(target);r['expires_at']=request.get('expires_at',time.time()+executor.c['block_seconds'])
            except (OSError,ValueError,RuntimeError):r['capture_unavailable']=True
            self.save(r)
            try:
                out=executor.execute(request,undo_token=r['id'])
                if out.get('verified') is not True:raise RuntimeError('Containment not verified')
                r['state']='contained'
                if action=='quarantine_account' and 'before' in r:
                    r['after']=account(target);b,a=r['before'],r['after']
                    r['eligible']=b['passwd_hash']!=a['passwd_hash'] or b['shadow_hash']!=a['shadow_hash']
                    r['eligible']=r['eligible'] and not b['password_empty'] and b['uid']==a['uid'] and a['passwd_hash']==b['quarantine_passwd_hash'] and a['shadow_hash']==b['quarantine_shadow_hash']
                elif action=='quarantine_persistence' and 'before' in r:
                    r['backup']=out['backup'];r['after']=file_state(r['backup']);r['eligible']=r['before']['sha256']==r['after']['sha256']
                elif action=='block_ip':
                    r['after']=ip_state(target);r['eligible']=r.get('before') is None and not r.get('capture_unavailable') and r['after']=={'comment':'aegis-undo-'+r['id']}
                self.save(r)
                return dict(out,undo_receipt=r['id'],undo_available=r['eligible'])
            except BaseException:
                r['state']='forward_uncertain';r['eligible']=False;self.save(r);raise
    def check(self,r):
        if r['state']=='restored':return 'Already restored; no action required'
        if r['state']!='contained' or not r['eligible']:raise ValueError('No verified reversible receipt; manual review required')
        if r['boot']!=boot():raise ValueError('Boot changed; manual review required')
        action,target=r['action'],r['target']
        if action in ('quarantine_account','quarantine_persistence') and any(other['id']!=r['id'] and other['action']==action and other['target']==target and other['state'] in ('prepared','contained','forward_uncertain') for other in self.entries()):
            raise ValueError('Another containment holds this target; manual review required')
        if action=='quarantine_account':
            if target in self.config.get('protected_users',[]):raise ValueError('Account is now protected')
            if account(target)!=r['after']:raise ValueError('Account or account database changed since containment')
            return 'Restore original shell, expiry and password-lock state; killed processes and sessions stay closed'
        if action=='quarantine_persistence':
            from persistence import lab_path
            if not lab_path(target) or str(pathlib.Path(target).parent.resolve())!=str(pathlib.Path(target).parent):raise ValueError('Target path changed or outside scope')
            parent=pathlib.Path(target).parent.stat()
            if parent.st_uid!=0 or parent.st_mode&0o022:raise ValueError('Unsafe destination directory')
            if os.path.lexists(target):raise ValueError('Destination exists; refusing overwrite')
            if file_state(r['backup'])!=r['after']:raise ValueError('Quarantine backup changed')
            return 'Restore exact file bytes and ownership/mode; cron may execute it immediately; systemd remains disabled/stopped'
        if action=='block_ip':
            current=ip_state(target)
            if current is None:return 'IP block already absent or expired; record a verified no-op'
            if current!={'comment':'aegis-undo-'+r['id']}:raise ValueError('IP block ownership changed')
            if any(other['id']!=r['id'] and other['action']=='block_ip' and other['target']==target and other['state']=='contained' and other.get('expires_at',0)>time.time() for other in self.entries()):raise ValueError('Another containment still requires this IP block')
            return 'Remove only the owned AEGIS IP block; other firewall rules stay unchanged'
        raise ValueError('This action is irreversible')
    def plan(self,identifier):
        r=self.read(identifier);description=self.check(r)
        public={k:r[k] for k in ('id','action','target','state')}
        public.update(effect=description,confirmation=digest(encoded(r)))
        if r['action']=='quarantine_account':
            public['restore']={k:r['before'][k] for k in ('uid','shell','expiry','locked')}
        elif r['action']=='quarantine_persistence':
            public['restore']={k:r['before'][k] for k in ('sha256','uid','gid','mode')}
            public['restore']['mode']=oct(public['restore']['mode']);public['backup']=r['backup']
        return public
    def apply(self,identifier,confirmation,reason):
        if not reason.strip() or len(reason)>500:raise ValueError('A reason of 1–500 characters is required')
        with self.lock():
            r=self.read(identifier)
            if r['state']=='restored':return {'id':identifier,'state':'restored','already_restored':True}
            operator={'uid':os.getuid(),'sudo_uid':os.environ.get('SUDO_UID'),'reason':reason,'time':time.time()}
            try:
                if digest(encoded(r))!=confirmation:raise ValueError('Receipt changed; generate a new plan')
                self.check(r)
            except (OSError,ValueError,RuntimeError) as exc:
                r['history'].append(dict(operator,state='refused',error=str(exc)));self.save(r);raise
            r['history'].append(dict(operator,state='undo_running'));r['state']='undo_running';self.save(r)
            try:
                action,target=r['action'],r['target']
                if action=='quarantine_account':restore_account(target,r['before'],r['after'])
                elif action=='quarantine_persistence':
                    # Copy via an exclusive link: preserve evidence and never overwrite an existing path.
                    parent=pathlib.Path(target).parent;fd,name=tempfile.mkstemp(prefix='.aegis-restore-',dir=parent)
                    try:
                        with os.fdopen(fd,'wb') as out:
                            os.fchown(out.fileno(),r['before']['uid'],r['before']['gid']);os.fchmod(out.fileno(),r['before']['mode'])
                            out.write(pathlib.Path(r['backup']).read_bytes());out.flush();os.fsync(out.fileno())
                        if file_state(name)['sha256']!=r['before']['sha256']:raise ValueError('Backup changed while restoring')
                        os.link(name,target,follow_symlinks=False)
                        dfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
                        try:os.fsync(dfd)
                        finally:os.close(dfd)
                    finally:os.unlink(name)
                    restored=file_state(target)
                    if any(restored[k]!=r['before'][k] for k in ('sha256','mode','uid','gid')):raise RuntimeError('File restore not verified')
                    if target.endswith('.service'):
                        from agent import run
                        run(['systemctl','daemon-reload'])
                elif action=='block_ip':
                    if ip_state(target) is not None:
                        from agent import run
                        family='blocked4' if ipaddress.ip_address(target).version==4 else 'blocked6'
                        run(['nft','delete','element','inet','defense_lab',family,'{',target,'}'])
                    if ip_state(target) is not None:raise RuntimeError('IP unblock not verified')
                r['state']='restored';r['history'].append(dict(operator,state='restored',completed_at=time.time()));self.save(r)
            except BaseException:
                r['state']='undo_uncertain';r['history'].append(dict(operator,state='undo_uncertain'));self.save(r);raise
            return {'id':identifier,'state':'restored','verified':True}

def main():
    if os.geteuid()!=0:raise SystemExit('Rollback requires root; use sudo')
    from agent import load_config
    p=argparse.ArgumentParser(description='AEGIS manual rollback: plan first, then apply with a reason')
    p.add_argument('operation',choices=('list','plan','apply'));p.add_argument('receipt',nargs='?');p.add_argument('--confirm');p.add_argument('--reason');p.add_argument('--config',default='/etc/defense-agent/config.json');args=p.parse_args()
    journal=Journal(load_config(args.config))
    try:
        if args.operation=='list':result=[{k:r.get(k) for k in ('id','time','action','target','state','eligible','history')} for r in journal.entries()]
        elif args.operation=='plan':result=journal.plan(args.receipt or '')
        else:result=journal.apply(args.receipt or '',args.confirm or '',args.reason or '')
        print(json.dumps(result,indent=2))
    except (OSError,ValueError,RuntimeError) as exc:raise SystemExit(str(exc))

if __name__=='__main__':main()
