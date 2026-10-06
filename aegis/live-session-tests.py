#!/usr/bin/env python3
"""Authorized LAB-only real SSH/session containment acceptance tests."""
import json,os,pathlib,pwd,sqlite3,subprocess,time,sys,shutil
DB='/var/lib/defense-agent/incidents.db';started=time.time();suffix=str(int(started))[-6:];results=[];processes=[];accounts=[];ns='defense-session-test';host='dsveth0';peer='dsveth1';tmp=pathlib.Path('/tmp/defense-session-'+suffix);tmp.mkdir(mode=0o700)
configpath=pathlib.Path('/etc/defense-agent/config.json');aipath=pathlib.Path('/etc/defense-agent/ai.json');original=configpath.read_text();original_ai=aipath.read_text();logpath=pathlib.Path('/etc/ssh/sshd_config.d/98-defense-session-lab.conf')
a='lab_sa_'+suffix;b='lab_sb_'+suffix;ok='lab_ok_'+suffix;target_a='lab_newa_'+suffix;target_b='lab_newb_'+suffix;target_ok='lab_approved_'+suffix;target_other='lab_other_'+suffix;target_second='lab_newc_'+suffix
ip='10.252.77.2';dst='10.252.77.1'
def cmd(args,check=True):
 p=subprocess.run(args,capture_output=True,text=True,timeout=15)
 if check and p.returncode:raise RuntimeError(str(args)+':'+p.stderr[:500])
 return p

def query(sql,args=()):
 deadline=time.monotonic()+12
 while True:
  c=sqlite3.connect(DB,timeout=3);c.row_factory=sqlite3.Row
  try:return [dict(x) for x in c.execute(sql,args)]
  except sqlite3.OperationalError as exc:
   if 'locked' not in str(exc) or time.monotonic()>=deadline:raise
   time.sleep(.1)
  finally:c.close()

def wait(fn,seconds=30):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  r=fn()
  if r:return r
  time.sleep(.15)
 return None

def case(user):
 for r in query("SELECT * FROM cases WHERE kind='ssh_session_account' AND created_at>=? ORDER BY created_at DESC",(started,)):
  if any(e['kind']=='ssh_session_open' and e['details']['user']==user for e in json.loads(r['evidence_json']).get('events',[])):return r
 return None

def record(name,passed,**data):
 results.append(dict(test=name,passed=bool(passed),**data));print(json.dumps(results[-1],ensure_ascii=False),flush=True)

def ssh(user,key,command,background=False):
 args=['ip','netns','exec',ns,'ssh','-o','BatchMode=yes','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-o','ConnectTimeout=2','-i',str(key),user+'@'+dst,command]
 if background:
  f=(tmp/(user+'.ssh.log')).open('w');p=subprocess.Popen(args,stdout=f,stderr=f,text=True);processes.append(p);return p
 return cmd(args,False)

def failures(user):
 codes=[ssh(user,tmp/'wrong','true').returncode for _ in range(5)];time.sleep(.5)
 r=query("SELECT details_json FROM correlation_events WHERE kind='ssh_failure' AND event_time>=?",(started,))
 count=sum(json.loads(x['details_json']).get('user')==user for x in r)
 if count<5:raise RuntimeError('Expected 5 real failed key authentications; got '+str(count))
 return codes

def configure(dedicated):
 cfg=json.loads(original);cfg.update(ssh_response_users=[a,b,ok],ssh_account_creator_allowlist=['root','labadmin',ok],ssh_dedicated_source_ips=[ip] if dedicated else [])
 configpath.write_text(json.dumps(cfg));cmd(['systemctl','restart','defense-agent','defense-executor']);time.sleep(.7)

def session_alive(user):
 return query("SELECT * FROM ssh_sessions WHERE active=1 AND event_time>=? AND json_extract(details_json,'$.user')=?",(started,user))

def defended(user):
 r=case(user);return r if r and r['status'] in ('defended','analysis_error','defense_error','observing','insufficient_evidence','authorized') else None

def verify(c):
 hs=query('SELECT * FROM case_status_history WHERE case_id=? ORDER BY time',(c['id'],)) if c else []
 result=json.loads(c['result_json']) if c else [];rec=next((h for h in hs if h['status']=='recognized'),None)
 return bool(rec and result and all(x['status']=='executed' and x['result']['verified'] and rec['time']<x['result']['executed_at'] for x in result)),hs
try:
 cmd(['systemctl','stop','defense-agent-ai'])
 logpath.write_text('LogLevel VERBOSE\n');cmd(['/usr/sbin/sshd','-t']);cmd(['systemctl','reload','ssh'])
 for key in ('good','wrong'):cmd(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(tmp/key)])
 for user in (a,b,ok):
  accounts.append(user);cmd(['useradd','-m','-s','/bin/bash',user]);cmd(['usermod','-p','*',user]);home=pathlib.Path(pwd.getpwnam(user).pw_dir);d=home/'.ssh';d.mkdir(mode=0o700);(d/'authorized_keys').write_text((tmp/'good.pub').read_text());os.chmod(d/'authorized_keys',0o600);cmd(['chown','-R',user+':'+user,str(d)])
 accounts.extend([target_a,target_b,target_ok,target_other,target_second])
 sudo=pathlib.Path('/etc/sudoers.d/defense-session-lab');sudo.write_text(a+' ALL=(root) NOPASSWD: /usr/sbin/useradd '+target_a+'\n'+b+' ALL=(root) NOPASSWD: /usr/sbin/useradd '+target_b+'\n'+ok+' ALL=(root) NOPASSWD: /usr/sbin/useradd '+target_ok+'\n');
 if '--two-accounts' in sys.argv:
  with sudo.open('a') as f:f.write(b+' ALL=(root) NOPASSWD: /usr/sbin/useradd '+target_second+'\n')
 os.chmod(sudo,0o440);cmd(['visudo','-cf',str(sudo)])
 configure(False)
 cmd(['ip','netns','add',ns]);cmd(['ip','link','add',host,'type','veth','peer','name',peer]);cmd(['ip','link','set',peer,'netns',ns]);cmd(['ip','addr','add',dst+'/30','dev',host]);cmd(['ip','link','set',host,'up']);cmd(['ip','netns','exec',ns,'ip','addr','add',ip+'/30','dev',peer]);cmd(['ip','netns','exec',ns,'ip','link','set',peer,'up']);cmd(['ip','netns','exec',ns,'ip','link','set','lo','up'])
 if '--dedicated-only' not in sys.argv:
  failures(a);time.sleep(3)
  r=query("SELECT * FROM cases WHERE kind='ssh_threshold' AND subject=? AND created_at>=? ORDER BY created_at DESC LIMIT 1",(ip,started));c=r[0] if r else None
  record('failed_logins_only_no_response',c and not json.loads(c['evidence_json']).get('allowed_actions') and cmd(['nft','get','element','inet','defense_lab','blocked4','{',ip,'}'],False).returncode!=0,case=c)
  normal=ssh(a,tmp/'good','sleep 120',True);wait(lambda:session_alive(a));time.sleep(3)
  record('failures_then_legal_login_stays_connected',normal.poll() is None and bool(session_alive(a)))
  cmd(['useradd',target_other]);time.sleep(3)
  record('other_session_action_not_attributed',normal.poll() is None and not case(a),sessions=session_alive(a))
  failures(ok);legit=ssh(ok,tmp/'good','sudo /usr/sbin/useradd '+target_ok+'; sleep 120',True);c=wait(lambda:case(ok))
  record('approved_account_creator_not_contained',c and not json.loads(c['evidence_json'])['allowed_actions'] and legit.poll() is None,case=c)
  # Same actor, another SSH session: the idle session must survive containment.
  attack=ssh(a,tmp/'good','sudo /usr/sbin/useradd '+target_a+'; sleep 120',True);c=wait(lambda:case(a))
  record('unauthorized_chain_waits_for_description',c and c['status']=='awaiting_analysis' and attack.poll() is None and pwd.getpwnam(target_a).pw_shell!='/usr/sbin/nologin',case=c)
  identity=c['subject'] if c else None;cmd(['systemctl','restart','defense-agent']);time.sleep(.5);c=case(a)
  record('audit_session_mapping_survives_restart',c and c['subject']==identity and c['status']=='awaiting_analysis',case=c)
  ai=json.loads(original_ai);ai['max_calls_per_hour']=40;aipath.write_text(json.dumps(ai));cmd(['systemctl','start','defense-agent-ai'])
  c=wait(lambda:defended(a),80);ordered,hs=verify(c)
  record('shared_source_only_specific_session_and_account_contained',c and c['status']=='defended' and ordered and pwd.getpwnam(target_a).pw_shell=='/usr/sbin/nologin' and wait(lambda:attack.poll() is not None,3) and normal.poll() is None and legit.poll() is None and cmd(['nft','get','element','inet','defense_lab','blocked4','{',ip,'}'],False).returncode!=0,case=c,history=hs,other_session_survived=normal.poll() is None)
 # Dedicated source: same proven chain additionally permits IP TTL block.
 cmd(['systemctl','stop','defense-agent-ai']);configure(True)
 if '--no-failures' not in sys.argv:failures(b)
 payload='sudo /usr/sbin/useradd '+target_b
 if '--two-accounts' in sys.argv:payload+='; sudo /usr/sbin/useradd '+target_second
 if '--short-session' not in sys.argv:payload+='; sleep 120'
 attack_b=ssh(b,tmp/'good',payload,True);c=wait(lambda:case(b));cmd(['systemctl','start','defense-agent-ai']);c=wait(lambda:defended(b),80);ordered,hs=verify(c)
 blocked=cmd(['nft','get','element','inet','defense_lab','blocked4','{',ip,'}'],False).returncode==0
 probe='import socket\ntry:\n socket.create_connection(('+repr(dst)+',22),timeout=1).close();print("connected")\nexcept Exception:print("blocked")'
 network_blocked=cmd(['ip','netns','exec',ns,'python3','-c',probe]).stdout.strip()=='blocked'
 if '--no-failures' in sys.argv:
  record('valid_login_then_unauthorized_change_contained_without_ip_block',c and c['status']=='defended' and ordered and not blocked and not network_blocked and pwd.getpwnam(target_b).pw_shell=='/usr/sbin/nologin',case=c,history=hs,source_still_reachable=not network_blocked)
 else:record('dedicated_source_blocked_only_after_confirmed_chain',c and c['status']=='defended' and ordered and blocked and network_blocked and pwd.getpwnam(target_b).pw_shell=='/usr/sbin/nologin',case=c,history=hs,firewall_verified=blocked,network_block_confirmed=network_blocked)
 if '--short-session' in sys.argv:
  record('short_session_still_contained',c and c['status']=='defended' and pwd.getpwnam(target_b).pw_shell=='/usr/sbin/nologin' and attack_b.poll() is not None,case=c)
 if '--two-accounts' in sys.argv:
  def all_contained():
   rows=query("SELECT * FROM cases WHERE kind='ssh_session_account' AND created_at>=?",(started,))
   relevant=[r for r in rows if any(e['kind']=='account_created' and e['subject'] in (target_b,target_second) for e in json.loads(r['evidence_json']).get('events',[]))]
   return relevant if len(relevant)==2 and all(r['status']=='defended' for r in relevant) else None
  both=wait(all_contained,80)
  record('two_accounts_same_session_both_contained',bool(both) and all(pwd.getpwnam(u).pw_shell=='/usr/sbin/nologin' for u in (target_b,target_second)),cases=both)
finally:
 for p in processes:
  if p.poll() is None:p.terminate()
 cmd(['nft','delete','element','inet','defense_lab','blocked4','{',ip,'}'],False)
 cmd(['ip','netns','del',ns],False);cmd(['ip','link','del',host],False)
 pathlib.Path('/etc/sudoers.d/defense-session-lab').unlink(missing_ok=True);logpath.unlink(missing_ok=True);cmd(['systemctl','reload','ssh'],False)
 configpath.write_text(original);aipath.write_text(original_ai);cmd(['systemctl','restart','defense-agent','defense-executor','defense-agent-ai'],False)
 for user in accounts:
  try:uid=pwd.getpwnam(user).pw_uid;cmd(['pkill','-KILL','-u',str(uid)],False);cmd(['userdel','-r',user],False)
  except KeyError:pass
 pathlib.Path('/tmp/session-results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2));shutil.rmtree(tmp)
if not all(r['passed'] for r in results):raise SystemExit(1)
