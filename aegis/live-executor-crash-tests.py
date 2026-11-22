#!/usr/bin/env python3
"""Disposable VM only: kill the actual executor at controlled action boundaries.

Fixture evidence and model assessment are synthetic. The quarantine operation, SIGKILL,
executor restart, durable receipt and rollback use real Linux filesystem operations.
"""
import hashlib,json,os,pathlib,secrets,signal,socket,subprocess,sys,tempfile,time
import agent,persistence,response
from rollback import Journal

HOOK=r'''
import os,pathlib,signal,sys
import agent,rollback
phase,marker,config=sys.argv[1:]
def pause():
 pathlib.Path(marker).write_text('ready')
 os.kill(os.getpid(),signal.SIGSTOP)
original=agent.Executor.execute
def execute(self,request,undo_token=None):
 if phase=='before_effect':pause()
 try:result=original(self,request,undo_token)
 except Exception as exc:
  pathlib.Path(marker+'.error').write_text(type(exc).__name__+': '+str(exc))
  raise
 if phase=='during_effect':pause()
 return result
agent.Executor.execute=execute
save=rollback.Journal.save
def save_hook(self,receipt):
 result=save(self,receipt)
 if phase=='after_receipt' and receipt.get('state')=='contained':pause()
 return result
rollback.Journal.save=save_hook
agent.serve_executor(agent.load_config(config))
'''


def check(name,condition):
 print(json.dumps({'test':name,'passed':bool(condition)}),flush=True)
 if not condition:raise AssertionError(name)


def prepare(engine,store,path,digest):
 now=time.time();sid='a'*32;ip='198.51.100.42';boot=engine.boot_id
 login=engine.normalize('app_login',ip,{'bypass':True,'success':True,'session':sid,'ip':ip,'event_id':'fixture-login'},'fixture-login',now-3)
 change=engine.normalize('persistence_change',str(path),{'operation':'CREATE','boot_id':boot,'pid':123,'start_ticks':321,'uid':'0','cgroup':'0::/system.slice/aegis-target-broker.service','path':str(path)},'fixture-file',now-2)
 job=engine.normalize('app_persistence_job','fixture',{'session':sid,'ip':ip,'login_id':'fixture-login','boot_id':boot,'broker_pid':123,'broker_start_ticks':321,'path':str(path),'sha256':digest},'fixture-job',now-1)
 identifier=engine.create_or_append('app_sql_persistence','fixture',job,[login,change])
 version=store.db.execute('SELECT version FROM cases WHERE id=?',(identifier,)).fetchone()[0]
 data=engine.snapshot(identifier,'app_sql_persistence','fixture',version)
 check('fixture_has_file_quarantine_action',data['allowed_actions'] and data['allowed_actions'][0]['action']=='quarantine_persistence')
 assessment={'attack':True,'confidence':.95,'evidence_ids':data['required_evidence_ids'],'proposed_actions':data['allowed_actions']}
 store.db.execute("UPDATE cases SET evidence_json=?,analysis_json=?,status='recognized' WHERE id=?",(json.dumps(data),json.dumps(assessment),identifier))
 response.prepare(engine,identifier,data)
 store.db.execute("UPDATE response_steps SET status='running',attempts=1 WHERE case_id=? AND position=0",(identifier,));store.db.commit()
 return {'case_id':identifier,'position':0,'version':version}


def start(config,phase,marker):
 path=pathlib.Path(config['executor_socket']);path.unlink(missing_ok=True)
 env=os.environ.copy();env['PYTHONPATH']=str(pathlib.Path(agent.__file__).resolve().parent)
 process=subprocess.Popen([sys.executable,'-c',HOOK,phase,str(marker),config['_config_path']],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  if process.poll() is not None:raise RuntimeError('Executor exited before readiness: '+process.stderr.read().decode()[:300])
  if path.exists():return process
  time.sleep(.05)
 process.kill();process.wait();raise TimeoutError('Executor did not create socket')


def main():
 if os.geteuid()!=0 or socket.gethostname()!='aegis-crash-check':raise SystemExit('Run as root only on a disposable aegis-crash-check VM')
 for unit in ('defense-agent.service','defense-response.service'):
  state=subprocess.run(['systemctl','is-active','--quiet',unit]).returncode
  if state not in (3,4):raise SystemExit('Agent state active or uncertain; refusing test')
 content=b'# inert AEGIS executor crash test\n';digest=hashlib.sha256(content).hexdigest()
 for phase in ('before_effect','during_effect','after_receipt'):
  target=pathlib.Path('/etc/cron.d/lab_aegis_ck'+secrets.token_hex(4));backup=persistence.QUARANTINE/(target.name+'.'+digest)
  if backup.exists():raise RuntimeError('Unexpected existing backup')
  created=False;store=None;worker=None
  try:
   with target.open('xb') as out:out.write(content)
   created=True;target.chmod(0o644)
   with tempfile.TemporaryDirectory(prefix='aegis-executor-kill-') as directory:
    root=pathlib.Path(directory);runtime=root/'run';runtime.mkdir();cfg=root/'config.json';marker=root/'marker'
    cfg.write_text(json.dumps({'response_mode':'enforce','lab_response_enabled':True,'data_dir':str(root),'runtime_dir':str(runtime),'executor_socket':str(runtime/'executor.sock')}))
    config=agent.load_config(cfg);store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,None)
    envelope=prepare(engine,store,target,digest);worker=start(config,phase,marker)
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as client:
     client.settimeout(5);client.connect(config['executor_socket']);client.send(json.dumps(envelope).encode())
    deadline=time.monotonic()+15
    while not marker.exists() and time.monotonic()<deadline:
     if worker.poll() is not None:raise RuntimeError('Executor exited before intended boundary')
     time.sleep(.05)
    if not marker.exists():
     error=marker.with_suffix('.error')
     raise TimeoutError('Executor did not reach intended boundary: '+(error.read_text()[:300] if error.exists() else 'no executor error'))
    worker.kill();worker.wait(timeout=5);worker=None
    check(phase+'_process_killed',True)
    entries=Journal(config).entries();check(phase+'_one_durable_receipt',len(entries)==1)
    receipt=entries[0];state=receipt['state']
    if phase=='before_effect':check('before_effect_original_unchanged',target.read_bytes()==content and not backup.exists() and state=='prepared')
    else:check(phase+'_real_file_moved',not target.exists() and backup.read_bytes()==content)
    worker=start(config,'no_hook',marker)
    try:result=agent.request_executor(config,envelope);error=None
    except RuntimeError as exc:result=None;error=str(exc)
    if phase in ('before_effect','during_effect'):
     check(phase+'_uncertain_requires_review',error is not None and 'uncertain' in error.lower())
     check(phase+'_retry_has_no_new_effect',len(Journal(config).entries())==1 and ((target.exists() and not backup.exists()) if phase=='before_effect' else (not target.exists() and backup.exists())))
    else:
     check('after_receipt_retry_reconciles',result is not None and result.get('reconciled') is True and result.get('undo_receipt')==receipt['id'])
     journal=Journal(config);plan=journal.plan(receipt['id']);undo=journal.apply(receipt['id'],plan['confirmation'],'Disposable executor crash test')
     check('after_receipt_rollback_restores',undo.get('state')=='restored' and target.read_bytes()==content)
    store.db.close();store=None
  finally:
   if worker:
    worker.kill();worker.wait(timeout=5)
   if store:store.db.close()
   if created:target.unlink(missing_ok=True);backup.unlink(missing_ok=True)
 print(json.dumps({'scope':'Real executor SIGKILL and filesystem containment; synthetic evidence and assessment; not end-to-end model accuracy.'}))
 print('EXECUTOR_CRASH_BOUNDARIES_PASSED')


if __name__=='__main__':main()
