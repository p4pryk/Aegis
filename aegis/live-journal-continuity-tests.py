#!/usr/bin/env python3
"""Exercise a real invalid journal cursor against an isolated fixture database."""
import json,os,pathlib,queue,socket,sys,tempfile,threading,time
from unittest.mock import patch
sys.path.insert(0,'/opt/defense-agent')
import agent,journal_stream,monitoring
checks=[]
def check(name,value):
    checks.append(bool(value));print(json.dumps({'test':name,'passed':bool(value)}),flush=True)
    if not value:raise AssertionError(name)
def main():
    if os.geteuid()!=0 or socket.gethostname()!='defense-lab-01':raise SystemExit('Run only as root on the isolated AEGIS lab VM')
    with tempfile.TemporaryDirectory(prefix='aegis-journal-gap-') as directory:
        root=pathlib.Path(directory);config=dict(agent.DEFAULTS,data_dir=directory)
        store=agent.Store(config)
        try:
            store.state('journal_cursor_ssh',{'cursor':'not-a-valid-journal-cursor'})
            checkpoints=journal_stream.Checkpoints(store);events=queue.Queue(maxsize=4096);health={}
            thread=threading.Thread(target=journal_stream.reader,args=(events,'ssh',config,checkpoints,health),daemon=True);thread.start()
            source,marker=events.get(timeout=30)
            check('Real journalctl rejects the invalid cursor before fallback',source=='journal_loss' and marker['source']=='ssh' and marker['reason']=='cursor_gap')
            with store.atomic():journal_stream.persist_loss(store,marker['source'],marker['reason'],marker['time'])
            check('Recorded gap does not advance the old cursor',store.state('journal_cursor_ssh')['cursor']=='not-a-valid-journal-cursor')
            restored=journal_stream.restore_health(store,'ssh',{})
            check('Gap survives restart without relying on a periodic health snapshot',bool(restored.get('cursor_gap_at')))
            engine=agent.CorrelatedEngine(config,store,None);now=time.time()
            (root/'producer.json').write_text(json.dumps({'boot_id':engine.boot_id,'pid':123,'start_ticks':1}))
            class Spool:
                path=root/'spool.db'
                def health(self):return {'rows':0,'oldest_seconds':0,'dropped':0}
            journals={'ssh':dict(restored,connected=True,pid=124,start_ticks=1),'journal_context':{'connected':True,'pid':125,'start_ticks':1}}
            with patch.object(monitoring,'process_state',return_value='running'),patch.object(monitoring,'service_active',return_value=True):
                sources=monitoring.source_states(engine,Spool(),journals,{},now,{'enabled':'1','lost':'0'})
            check('Restored SSH reader health reports GAP',next(row for row in sources if row['name']=='SSH journal')['status']=='GAP')
        finally:store.db.close()
    print(json.dumps({'passed':sum(checks),'total':len(checks)}))
if __name__=='__main__':main()
