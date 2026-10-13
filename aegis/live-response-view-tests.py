"""Isolated VM: validate unprivileged views against real rollback-test receipts."""
import base64,gzip,json,os,pathlib,pty,select,subprocess,sys,time
sys.path.insert(0,'/opt/defense-agent')
from rollback import Journal
from agent import load_config
journal=Journal(load_config())
rows=journal.entries()
assert any(r['state']=='restored' for r in rows)
assert any(r['state']=='undo_uncertain' for r in rows)
assert any(any(h['state']=='refused' for h in r.get('history',[])) for r in rows)
code='''
import sys,json,pathlib,os,time
sys.path.insert(0,'/opt/defense-agent')
import console
from response_view import history_lines
snapshot=console.read_snapshot('/var/lib/defense-agent/incidents.db')
assert snapshot['response_history_status']=='AVAILABLE'
assert any(r['state']=='restored' for r in snapshot['responses'])
assert any(r['state']=='undo_uncertain' for r in snapshot['responses'])
assert 'REVIEW REQUIRED' in '\\n'.join(history_lines(snapshot,120,True))
for r in snapshot['responses']:
 assert not any(k in r for k in ('before','after','history','token','reason'))
try:
 list(pathlib.Path('/var/lib/defense-agent/rollback').iterdir())
 raise AssertionError('Private receipts readable')
except PermissionError:pass
path=next(pathlib.Path('/var/lib/defense-agent/response-history').glob('*.json'))
try:
 with path.open('a'):pass
 raise AssertionError('Public receipt writable')
except PermissionError:pass
frames={mode:[{'text':str(line),'level':getattr(line,'level','neutral')} for line in console.render(snapshot,120,42,mode=mode)] for mode in ('responses','review')}
pathlib.Path('/tmp/aegis-view-frames.json').write_text(json.dumps(frames))
print('PASS: unprivileged read, private denial, write denial, restored state, review state, public schema')
'''
subprocess.run(['runuser','-u','defense-ai','--','python3','-c',code],check=True)
master,slave=pty.openpty()
process=subprocess.Popen(['runuser','-u','defense-ai','--','python3','/opt/defense-agent/console.py','--responses','--width','121','--height','42'],stdin=slave,stdout=slave,stderr=slave);os.close(slave)
def receive(needle):
    end=time.monotonic()+8;output=b''
    while time.monotonic()<end:
        if select.select([master],[],[],.2)[0]:
            output+=os.read(master,65536)
            if needle in output:return output
    raise AssertionError('Terminal state unavailable: '+str(needle))
try:
    receive(b'RESPONSE HISTORY')
    os.write(master,b'7');receive(b'REVIEW REQUIRED')
    os.write(master,b'j');receive(b'REVIEW REQUIRED')
    os.write(master,b'k');receive(b'REVIEW REQUIRED')
    os.write(master,b'6');receive(b'RESPONSE HISTORY')
    os.write(master,b'q');assert process.wait(timeout=5)==0
    print('PASS: real PTY navigation, scrolling and clean exit')
finally:
    if process.poll() is None:process.terminate();process.wait(timeout=5)
    os.close(master)
print('VIEW_LIVE_TESTS_COMPLETE: 7 checks')
