#!/usr/bin/env python3
"""Bounded, intentionally vulnerable authentication target with a separate lab broker."""
import argparse,http.server,ipaddress,json,os,pathlib,pwd,re,secrets,socket,sqlite3,struct,subprocess,time,uuid
ROOT=pathlib.Path('/var/lib/aegis-target');SOCKET='/run/aegis-target/broker.sock';LOG='/var/log/defense-agent/application.jsonl'
def rpc(data):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(12);s.connect(SOCKET);s.send(json.dumps(data).encode());return json.loads(s.recv(16384))
def ticks(pid):return int(pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19])
def broker():
    ROOT.mkdir(exist_ok=True,mode=0o700);db=sqlite3.connect(ROOT/'target.db')
    db.executescript("CREATE TABLE IF NOT EXISTS users(name TEXT PRIMARY KEY,password TEXT,role TEXT);CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,ip TEXT,bypass INTEGER,login_id TEXT,created REAL,revoked INTEGER DEFAULT 0);INSERT OR IGNORE INTO users VALUES('admin','training-admin-only','admin');INSERT OR IGNORE INTO users VALUES('viewer','training-viewer-only','viewer');");db.commit()
    path=pathlib.Path(SOCKET);path.parent.mkdir(exist_ok=True);path.unlink(missing_ok=True)
    server=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);server.bind(SOCKET);os.chown(SOCKET,0,pwd.getpwnam('aegis-target').pw_gid);os.chmod(SOCKET,0o660);server.listen(8)
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();broker_ticks=ticks(os.getpid())
    def emit(kind,**data):
        event=dict(type=kind,time=time.time(),event_id=uuid.uuid4().hex,boot_id=boot,broker_pid=os.getpid(),broker_start_ticks=broker_ticks,**data)
        with open(LOG,'a') as f:f.write(json.dumps(event)+'\n')
        os.chmod(LOG,0o600);return event['event_id']
    while True:
        client,_=server.accept()
        with client:
            client.settimeout(3)
            try:
                peer_pid,uid,_=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));raw=client.recv(8192);d=json.loads(raw);op=d.get('op')
                if op=='revoke':
                    if uid!=0 or not re.fullmatch('[a-f0-9]{32}',d.get('session','')):raise ValueError('Unauthorized response')
                    db.execute('UPDATE sessions SET revoked=1 WHERE id=?',(d['session'],));db.commit();row=db.execute('SELECT revoked FROM sessions WHERE id=?',(d['session'],)).fetchone()
                    result={'verified':bool(row and row[0]==1),'revoked':True}
                else:
                    if uid!=pwd.getpwnam('aegis-target').pw_uid:raise ValueError('Unauthorized collector')
                    groups=pathlib.Path(f'/proc/{peer_pid}/cgroup').read_text()
                    if 'aegis-target.service' not in groups:raise ValueError('Unexpected collector unit')
                    ip=str(ipaddress.ip_address(d['ip']));request_id=uuid.uuid4().hex
                    db.execute('DELETE FROM sessions WHERE created<?',(time.time()-600,));db.commit()
                    if db.execute('SELECT count(*) FROM sessions').fetchone()[0]>=1000:raise ValueError('Training session limit reached')
                    if op=='login':
                        name=d.get('username','');password=d.get('password','')
                        if not isinstance(name,str) or not isinstance(password,str) or len(name)>256 or len(password)>256:raise ValueError('Invalid input')
                        # Deliberate SQL injection; synthetic credentials only, no extensions or scripts.
                        try:row=db.execute("SELECT name,role FROM users WHERE name='"+name+"' AND password='"+password+"'").fetchone()
                        except sqlite3.Error:row=None
                        baseline=db.execute('SELECT name,role FROM users WHERE name=? AND password=?',(name,password)).fetchone()
                        bypass=bool(row and not baseline);sid=secrets.token_hex(16) if row and row[1]=='admin' else None
                        login_id=emit('app_login',request_id=request_id,ip=ip,bypass=bypass,suspicious=bool(re.search(r"(?i)(?:union\s+select|or\s+\d|--|/\*)",name+' '+password)),success=bool(row),admin=bool(sid),session=sid)
                        if sid:db.execute('INSERT INTO sessions VALUES(?,?,?,?,?,0)',(sid,ip,int(bypass),login_id,time.time()));db.commit()
                        result={'status':200 if sid else 401,'authenticated':bool(sid),'session':sid,'request_id':request_id}
                    elif op=='check_session':
                        sid=d.get('session','');row=db.execute('SELECT ip,created,revoked FROM sessions WHERE id=?',(sid,)).fetchone()
                        result={'status':200 if row and row[0]==ip and not row[2] and time.time()-row[1]<=600 else 403}
                    elif op=='persistence':
                        sid=d.get('session','');row=db.execute('SELECT ip,bypass,login_id,created,revoked FROM sessions WHERE id=?',(sid,)).fetchone()
                        if not row or row[4] or time.time()-row[3]>600 or row[0]!=ip:result={'status':403,'error':'Session unavailable'}
                        else:
                            label=d.get('name','');artifact=d.get('artifact','')
                            if not isinstance(label,str) or not re.fullmatch(r'[a-z0-9_-]{1,20}',label) or artifact not in ('cron','systemd'):raise ValueError('Invalid training artifact')
                            filename='lab_aegis_'+label.replace('-','_') if artifact=='cron' else 'lab-aegis-'+label+'.service'
                            target=pathlib.Path('/etc/cron.d' if artifact=='cron' else '/etc/systemd/system')/filename
                            if sum(x.name.startswith('lab_aegis_') for x in pathlib.Path('/etc/cron.d').glob('*'))+sum(x.name.startswith('lab-aegis-') for x in pathlib.Path('/etc/systemd/system').glob('*.service'))>=20:raise ValueError('Training artifact limit reached')
                            body=b'*/5 * * * * root /usr/bin/true\n' if artifact=='cron' else b'[Unit]\nDescription=AEGIS training unit\n[Service]\nExecStart=/usr/bin/sleep 600\n[Install]\nWantedBy=multi-user.target\n'
                            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
                            with os.fdopen(fd,'wb') as file:file.write(body)
                            if artifact=='systemd':
                                subprocess.run(['systemctl','daemon-reload'],check=True,timeout=8)
                                subprocess.run(['systemctl','enable','--now',filename],check=True,timeout=8,stdout=subprocess.DEVNULL)
                            import hashlib
                            emit('app_persistence_job',request_id=request_id,ip=ip,session=sid,login_id=row[2],bypass=bool(row[1]),path=str(target),sha256=hashlib.sha256(body).hexdigest(),artifact=artifact)
                            result={'status':201,'created':str(target),'request_id':request_id}
                    elif op=='create':
                        sid=d.get('session','');row=db.execute('SELECT ip,bypass,login_id,created,revoked FROM sessions WHERE id=?',(sid,)).fetchone()
                        if not row or row[4] or time.time()-row[3]>600 or row[0]!=ip:result={'status':403,'error':'Session unavailable'}
                        else:
                            name=d.get('user','')
                            if not re.fullmatch(r'lab_http_[a-z0-9_]{1,15}',name):raise ValueError('Only lab_http_ accounts are permitted')
                            count=sum(x.startswith('lab_http_') for x in pathlib.Path('/etc/passwd').read_text().splitlines())
                            if count>=20:raise ValueError('Training account limit reached')
                            process=subprocess.Popen(['/usr/sbin/useradd','-M','-s','/bin/bash',name],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                            pid=process.pid;_,err=process.communicate(timeout=8)
                            if process.returncode:raise ValueError('Account creation failed')
                            account=pwd.getpwnam(name)
                            emit('app_account_job',request_id=request_id,ip=ip,session=sid,login_id=row[2],bypass=bool(row[1]),user=name,account_uid=account.pw_uid,pid=pid)
                            result={'status':201,'created':name,'request_id':request_id}
                    else:raise ValueError('Unknown operation')
                client.send(json.dumps(result).encode())
            except Exception as exc:
                try:client.send(json.dumps({'status':400,'error':str(exc)[:120]}).encode())
                except OSError:pass
class Handler(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup();self.connection.settimeout(5)
    def log_message(self,*args):pass
    def do_GET(self):
        body=b'AEGIS training target\nPOST /login {username,password}\nPOST /accounts {session,user}\nPOST /persistence {session,artifact,name}\nPOST /shell {session}\nSynthetic credentials: admin / training-admin-only\nIntentionally vulnerable. Isolated training use only.\n';self.send_response(200);self.end_headers();self.wfile.write(body)
    def do_POST(self):
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=2048:raise ValueError('Invalid body size')
            d=json.loads(self.rfile.read(size));d['op']={'/login':'login','/accounts':'create','/persistence':'persistence','/shell':'check_session'}[self.path];d['ip']=self.client_address[0];result=rpc(d)
            if self.path=='/shell' and result.get('status')==200:
                subprocess.run(['/bin/sh','-c','sleep 0.2; /usr/bin/true'],timeout=3,check=True)
                result={'status':200,'executed':'fixed training command'}
        except Exception:result={'status':400,'error':'Invalid request'}
        body=json.dumps(result).encode();self.send_response(result.get('status',200));self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['broker','http']);a=p.parse_args()
    if a.mode=='broker':broker()
    else:http.server.HTTPServer(('0.0.0.0',8081),Handler).serve_forever()
