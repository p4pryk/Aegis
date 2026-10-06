#!/usr/bin/env python3
"""Isolated LAB executor acceptance: actual TCP drop, counters, TTL and guards.
This exercises executor mechanics, not incident correlation or model authorization.
"""
import json,pathlib,subprocess,sys,time
sys.path.insert(0,'/opt/defense-agent')
from agent import DEFAULTS,Executor
ns='defense-ttl-test';host='dtveth0';peer='dtveth1';ip='10.252.78.2';dst='10.252.78.1';results=[]
def cmd(args,check=True):
 r=subprocess.run(args,capture_output=True,text=True,timeout=10)
 if check and r.returncode:raise RuntimeError(str(args)+': '+r.stderr[:300])
 return r

def probe():
 script='import socket\ntry:\n socket.create_connection(('+repr(dst)+',8080),timeout=.4).close();print("connected")\nexcept OSError:print("blocked")'
 return cmd(['ip','netns','exec',ns,'python3','-c',script]).stdout.strip()

def drops():
 data=json.loads(cmd(['nft','-j','list','chain','inet','defense_lab','ingress']).stdout)
 return sum(x['counter']['packets'] for r in data['nftables'] if 'rule' in r for x in r['rule']['expr'] if 'counter' in x)

def record(name,passed,**kwargs):results.append(dict(test=name,passed=bool(passed),**kwargs))
try:
 cfg=DEFAULTS.copy();cfg.update(json.loads(pathlib.Path('/etc/defense-agent/config.json').read_text()));cfg['block_seconds']=3
 executor=Executor(cfg);executor.firewall_init()
 cmd(['ip','netns','add',ns]);cmd(['ip','link','add',host,'type','veth','peer','name',peer]);cmd(['ip','link','set',peer,'netns',ns]);cmd(['ip','addr','add',dst+'/30','dev',host]);cmd(['ip','link','set',host,'up']);cmd(['ip','netns','exec',ns,'ip','addr','add',ip+'/30','dev',peer]);cmd(['ip','netns','exec',ns,'ip','link','set',peer,'up']);cmd(['ip','netns','exec',ns,'ip','link','set','lo','up'])
 record('tcp_reachable_before_block',probe()=='connected')
 before=drops();start=time.monotonic();out=executor.execute({'action':'block_ip','ip':ip});during=probe();after=drops()
 record('real_tcp_dropped_and_counter_increased',out['verified'] and during=='blocked' and after>before,counter_before=before,counter_after=after,result=out)
 second=executor.execute({'action':'block_ip','ip':ip});record('duplicate_block_is_idempotent',second['already_present'])
 time.sleep(max(0,3.5-(time.monotonic()-start)));present=cmd(['nft','get','element','inet','defense_lab','blocked4','{',ip,'}'],False).returncode==0
 record('ttl_expires_and_tcp_recovers',not present and probe()=='connected',elapsed_seconds=round(time.monotonic()-start,3))
 for protected in ['127.0.0.1',*cfg['protected_ips']]:
  try:executor.execute({'action':'block_ip','ip':protected});rejected=False
  except ValueError:rejected=True
  record('protected_ip_rejected_'+protected,rejected)
finally:
 cmd(['nft','delete','element','inet','defense_lab','blocked4','{',ip,'}'],False);cmd(['ip','netns','del',ns],False);cmd(['ip','link','del',host],False)
 pathlib.Path('/tmp/defense-review-firewall-results.json').write_text(json.dumps(results,indent=2));print(json.dumps(results,indent=2))
if not results or not all(r['passed'] for r in results):raise SystemExit(1)
