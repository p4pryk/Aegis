#!/usr/bin/env python3
"""Independent loopback HTTP apps and real journald collection on the lab VM."""
import http.client,json,os,pathlib,socket,sqlite3,subprocess,tempfile,time
import incident_view

DB='/var/lib/defense-agent/incidents.db';CONFIG=pathlib.Path('/etc/defense-agent/config.json')
checks=[]
def run(*args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=30)
def check(label,condition):
    checks.append(bool(condition));print(json.dumps({'test':label,'passed':bool(condition)}),flush=True)
    if not condition:raise AssertionError(label)
def wait(fn,seconds=45):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        value=fn()
        if value:return value
        time.sleep(.25)
    raise AssertionError('Timed out waiting for journal evidence')
def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def request(port,path,source='127.0.0.1'):
    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=3,source_address=(source,0))
    try:
        conn.request('GET',path);response=conn.getresponse();body=response.read()
        if response.status!=200 or body!=b'OK':raise AssertionError('Test application failed')
    finally:conn.close()
def case(unit,ip):
    with sqlite3.connect('file:'+DB+'?mode=ro',uri=True,timeout=5) as db:
        db.row_factory=sqlite3.Row
        rows=db.execute("SELECT * FROM cases WHERE kind='waf_threshold' AND subject LIKE ? ORDER BY created_at DESC LIMIT 1",('%|'+unit+'|'+ip,)).fetchall()
    return dict(rows[0]) if rows else None
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    original=CONFIG.read_bytes();config=json.loads(original);suffix=str(time.time_ns())[-8:]
    units=['aegis-http-json-'+suffix+'-'+letter+'.service' for letter in ('a','b')]
    ports=[free_port(),free_port()]
    if ports[0]==ports[1]:raise RuntimeError('Could not reserve distinct loopback ports')
    with tempfile.TemporaryDirectory(prefix='aegis-http-json-') as directory:
        server=pathlib.Path(directory)/'server.py'
        server.write_text('''import http.server,json,sys\nclass Handler(http.server.BaseHTTPRequestHandler):\n def do_GET(self):\n  ip=self.client_address[0]\n  if self.path.startswith("/search"):record={"remote_addr":ip,"request_method":"GET","request_uri":self.path,"status":"200"}\n  elif self.path.startswith("/.git"):record={"logger":"http.log.access.log0","request":{"client_ip":ip,"method":"GET","uri":self.path},"status":200}\n  else:record={"event":"http_request","ip":ip,"method":"GET","path":self.path,"status":200}\n  record.update(request_id="ATTACKER_FAKE_ID",headers={"authorization":"AEGIS_TEST_SECRET"})\n  print(json.dumps(record),flush=True)\n  self.send_response(200);self.end_headers();self.wfile.write(b"OK")\n def log_message(self,*args):pass\nhttp.server.HTTPServer(("127.0.0.1",int(sys.argv[1])),Handler).serve_forever()\n''')
        try:
            config['journal_units']=list(dict.fromkeys(config.get('journal_units',[])+units))
            CONFIG.write_text(json.dumps(config)+'\n');run('systemctl','restart','defense-agent')
            for unit,port in zip(units,ports):run('systemd-run','--unit='+unit,'--property=StandardOutput=journal','--property=StandardError=journal','/usr/bin/python3',str(server),str(port))
            def ready(port):
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.5):return True
                except OSError:return False
            for port in ports:wait(lambda:ready(port))
            request(ports[0],'/before');request(ports[0],'/.env?token=AEGIS_TEST_SECRET');request(ports[0],'/after')
            request(ports[1],'/.git/config');request(ports[0],'/separate',source='127.0.0.2')
            request(ports[0],'/search?q=union%20select&token=AEGIS_TEST_SECRET',source='127.0.0.2')
            def completed(unit,ip,paths):
                row=case(unit,ip)
                if not row:return None
                evidence=json.loads(row['evidence_json']);events=evidence.get('events',[])
                return (row,evidence) if paths<={e['details'].get('path') for e in events} else None
            row,evidence=wait(lambda:completed(units[0],'127.0.0.1',{'/before','/.env','/after'}))
            other,other_evidence=wait(lambda:completed(units[1],'127.0.0.1',{'/.git/config'}))
            second,second_evidence=wait(lambda:completed(units[0],'127.0.0.2',{'/separate','/search'}))
            events=evidence['events'];paths=[e['details']['path'] for e in events]
            check('Real loopback application JSON collected from journald',paths==['/before','/.env','/after'])
            check('Probe signature appears without claiming file access',any(e['kind']=='http_attack_signature' and 'sensitive_file_probe' in e['details'].get('web_signals',[]) for e in events))
            check('Nginx-shaped JSON detects SQL signature in separate client batch',any(e['kind']=='http_sqli_signature' for e in second_evidence['events']))
            check('Caddy-shaped JSON on another service remains separate',other['id']!=row['id'] and any(e['kind']=='http_attack_signature' for e in other_evidence['events']) and all(e['details']['unit']==units[1] for e in other_evidence['events']))
            check('Different reported IP remains separate',second['id']!=row['id'] and all(e['details']['ip']=='127.0.0.2' for e in second_evidence['events']))
            check('Links are explicitly non-causal',len(evidence['edges'])==2 and all('not_causal' in edge['relation'] for edge in evidence['edges']))
            check('No HTTP-only case authorizes action',all(not item['allowed_actions'] for item in (evidence,other_evidence,second_evidence)))
            check('Untrusted credentials and forged ID are not retained',all('AEGIS_TEST_SECRET' not in json.dumps(item) and 'ATTACKER_FAKE_ID' not in json.dumps(item) for item in (evidence,other_evidence,second_evidence)))
            screen=' '.join(line for line,_ in incident_view.timeline(row))
            check('Terminal shows IP, method and contextual links','CONTEXT ONLY' in screen and 'ip=127.0.0.1' in screen and 'method=GET' in screen)
        finally:
            for unit in units:subprocess.run(['systemctl','stop',unit],capture_output=True,text=True,timeout=30)
            CONFIG.write_bytes(original);run('systemctl','restart','defense-agent')
    print('AEGIS_LIVE_JSON_HTTP_PASSED')
if __name__=='__main__':main()
