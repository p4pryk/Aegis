#!/usr/bin/env python3
"""Read-only terminal dashboard. Standard library; no impact on defense services."""
import argparse, datetime, json, os, re, select, shutil, signal, sys, textwrap, time, unicodedata, sqlite3

from presentation import case_display, event_display, action_display

class Line(str):
    def __new__(cls,text,level='neutral',segments=None):
        obj=super().__new__(cls,text);obj.level=level;obj.segments=segments;return obj

COLORS={'neutral':'\x1b[0m','warning':'\x1b[33m','critical':'\x1b[31m','defended':'\x1b[94m'}
MARKERS={'neutral':'[i]','warning':'[!]','critical':'[x]','defended':'[<>]'}

def painted(line):
    parts=getattr(line,'segments',None) or [(str(line),getattr(line,'level','neutral'))]
    return ''.join(COLORS[level]+text for text,level in parts)+'\x1b[0m'

NAME = 'A E G I S'
STATES = {'authorized':'AUTHORIZED', 'collecting':'COLLECTING', 'awaiting_analysis':'ANALYZING', 'recognized':'ASSESSED', 'defended':'DEFENDED', 'observing':'MONITORING', 'insufficient_evidence':'INSUFFICIENT EVIDENCE', 'analysis_error':'ANALYSIS ERROR', 'defense_error':'RESPONSE ERROR'}
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]')

def safe(value):
    value=ANSI.sub('',str(value))
    return ''.join(c if c=='\n' or not unicodedata.category(c).startswith('C') else ' ' for c in value)

def cells(value):
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W','F') else 1 for c in value)

def fit(value,width):
    value=safe(value).replace('\n',' ');out='';used=0
    for c in value:
        n=cells(c)
        if used+n>width:break
        out+=c;used+=n
    return out+' '*(width-used)

def stamp(value):
    try:return datetime.datetime.fromtimestamp(float(value)).strftime('%H:%M:%S')
    except (ValueError,TypeError,OverflowError,OSError):return '--:--:--'

def decoded(value,default):
    try:return json.loads(value) if isinstance(value,str) else value
    except (ValueError,TypeError):return default

def wrapped(value,width,level='neutral'):
    # Break long subjects and model text; fit() additionally bounds display cells.
    return [Line(fit(line,width),level) for line in textwrap.wrap(safe(value).replace('\n',' '),width=max(1,width),break_long_words=True,break_on_hyphens=False)] or [Line(fit('',width),level)]

def logo(width):
    if width<74:
        return [fit('   .-------.   '+NAME,width),fit('   |  /\\  |   DEFENSE AGENT',width),fit('   | /++\\ |   ',width),fit('   \\  ++  /',width),fit('    \\___/    ',width)]
    left=['   .----------.','   |   /\\     |','   |  /++\\    |','   |  \\++/    |','   \\    ++    /','    \\________/']
    right=['.----------.   ','|     /\\   |   ','|    /++\\  |   ','|    \\++/  |   ','\\    ++    /   ',' \\________/    ']
    middle=['',NAME,'DEFENSE AGENT','','','']
    middle_width=width-32
    return [fit(l,16)+fit(m.center(middle_width),middle_width)+fit(r,16) for l,m,r in zip(left,middle,right)]

def case_lines(data,width):
    lines=[]
    for case in sorted(data.get('cases',[]),key=lambda c:c.get('updated_at',0),reverse=True):
        evidence=decoded(case.get('evidence_json'),{}) or {};analysis=decoded(case.get('analysis_json'),{}) or {};actions=decoded(case.get('result_json'),[]) or []
        login=next((e for e in evidence.get('events',[]) if e.get('kind')=='ssh_session_open'),None)
        account=next((e.get('subject') for e in evidence.get('events',[]) if e.get('kind')=='account_created'),None)
        view=case_display(case)
        path=next((e.get('details',{}).get('path') for e in evidence.get('events',[]) if e.get('kind')=='persistence_change'),None)
        focus=account or path
        title=view['kind_label']+((': '+str(focus)) if focus else '')
        lines.extend(wrapped(MARKERS[view['level']]+' '+stamp(case.get('updated_at'))+' ['+view['label']+'] '+str(title),width,view['level']))
        lines.extend(wrapped(view['status_label'],width,view['level']))
        if login:
            d=login.get('details',{});lines.extend(wrapped('SSH '+str(d.get('user','--'))+' @ '+str(d.get('ip','--'))+' / session '+str(d.get('session','--')),width))
        lines.extend(wrapped('Evidence: '+str(len(evidence.get('events',[])))+' / links: '+str(len(evidence.get('edges',[]))),width))
        # The model may include an application session token in its narrative.
        summary=re.sub(r'\b[0-9a-f]{32}\b','[session redacted]',view['summary'],flags=re.I)
        lines.extend(wrapped(summary,width))
        if isinstance(actions,list):
            for action in actions:
                av=action_display(action)
                lines.extend(wrapped(MARKERS[av['level']]+' '+av['message']+' / '+av['label'],width,av['level']))
        lines.append('-'*width)
    return lines or wrapped('Waiting for the first incident.',width)

def event_lines(data,width):
    lines=[]
    for event in sorted(data.get('observations',[]),key=lambda e:e.get('time',0),reverse=True):
        view=event_display(event)
        lines.extend(wrapped(MARKERS[view['level']]+' '+stamp(event.get('time'))+' '+str(event.get('source','--'))+' / '+str(event.get('subject','--')),width,view['level']))
        lines.extend(wrapped(view['message'],width,view['level']));lines.append('')
    return lines or wrapped('Waiting for events.',width)

def render(data,width=104,height=32,mode='both',paused=False,error=None,now=None):
    width=max(1,width);height=max(1,height);now=time.time() if now is None else now
    if width<32 or height<12:
        compact=[fit('[<>] AEGIS / DEFENSE AGENT',width),fit('Enlarge the terminal window.',width)]
        return (compact+[' '*width]*height)[:max(0,height-1)]+[fit('[q] quit',width)]
    lines=logo(width);lines.append('='*width)
    heartbeat=data.get('heartbeat',{});healthy=0<=now-heartbeat.get('time',0)<15
    status='DATA UNAVAILABLE' if error else 'DISPLAY PAUSED' if paused else 'AGENT ONLINE' if healthy else 'CHECK AGENT'
    lines.append(fit('['+status+']  '+stamp(now)+'  |  audit / SSH / application / journald',width))
    metrics=data.get('metrics',[]);total=sum(m.get('total',0) for m in metrics)
    queue=sum(c.get('status') in ('collecting','awaiting_analysis') for c in data.get('cases',[]))
    health=data.get('sensor_health',{});journal=health.get('journal');context=health.get('journal_context')
    drops='--' if not isinstance(journal,dict) or not isinstance(context,dict) else str(journal.get('dropped_events',0)+context.get('dropped_events',0))
    lines.append(fit('Events: '+str(total)+'  |  Cases: '+str(len(data.get('cases',[])))+'  |  Pending in view: '+str(queue)+'  |  Audit lost: '+str(health.get('audit',{}).get('lost','--'))+'  |  Journal queue drops: '+drops,width))
    if error:lines.append(fit('Event store unavailable. Showing the last received state.',width))
    body_rows=max(0,height-len(lines)-2)
    if mode=='both' and width>=100:
        left=max(32,int((width-3)*.40));right=width-left-3
        events=[fit('EVENTS / LATEST FIRST',left),'-'*left]+event_lines(data,left)
        cases=[fit('ASSESSMENT / RESPONSE',right),'-'*right]+case_lines(data,right)
        for i in range(body_rows):
            ev=events[i] if i<len(events) else '';ca=cases[i] if i<len(cases) else ''
            parts=[(fit(ev,left),getattr(ev,'level','neutral')),(' | ','neutral'),(fit(ca,right),getattr(ca,'level','neutral'))]
            lines.append(Line(''.join(t for t,_ in parts),segments=parts))
    elif mode=='both':
        case_rows=max(0,body_rows//2-1);event_rows=max(0,body_rows-case_rows-2)
        lines.append(fit('ASSESSMENT / RESPONSE',width));lines.extend((case_lines(data,width)+[' '*width]*case_rows)[:case_rows])
        lines.append(fit('EVENTS / LATEST FIRST',width));lines.extend((event_lines(data,width)+[' '*width]*event_rows)[:event_rows])
    else:
        title='EVENTS' if mode=='events' else 'ASSESSMENT / RESPONSE'
        body=event_lines(data,width) if mode=='events' else case_lines(data,width)
        lines.extend(([fit(title,width),'-'*width]+body+[' '*width]*body_rows)[:body_rows])
    lines=lines[:max(0,height-2)]
    lines+=[' '*width]*(max(0,height-2)-len(lines))
    lines.append('-'*width);lines.append(fit('[1] all  [2] events  [3] cases  [space] pause  [q] quit',width))
    return lines[:height]

def read_snapshot(database):
    # Read-only URI and query_only enforce a viewer with no database mutations.
    from pathlib import Path
    uri=Path(database).resolve().as_uri()+'?mode=ro'
    conn=sqlite3.connect(uri,uri=True,timeout=2)
    try:
        conn.execute('PRAGMA query_only=ON');conn.row_factory=sqlite3.Row
        cases=[dict(r) for r in conn.execute('SELECT * FROM cases ORDER BY updated_at DESC LIMIT 40')]
        events=[dict(r) for r in conn.execute('SELECT * FROM observations ORDER BY rowid DESC LIMIT 60')]
        metrics=[dict(r) for r in conn.execute('SELECT * FROM sensor_metrics')]
        states={r['key']:json.loads(r['value']) for r in conn.execute("SELECT * FROM state WHERE key IN ('heartbeat','sensor_health')")}
        return {'cases':cases,'observations':events,'metrics':metrics,**states}
    finally:conn.close()

def main():
    parser=argparse.ArgumentParser(description='AEGIS Defense Agent: live terminal interface')
    parser.add_argument('--database',default='/var/lib/defense-agent/incidents.db');parser.add_argument('--snapshot',action='store_true');parser.add_argument('--data-file');parser.add_argument('--width',type=int);parser.add_argument('--height',type=int)
    args=parser.parse_args();data={};error=None
    try:data=json.loads(open(args.data_file).read()) if args.data_file else read_snapshot(args.database)
    except (OSError,ValueError,sqlite3.Error):error=True
    size=shutil.get_terminal_size((104,32));width=args.width or size.columns;height=args.height or size.lines
    if args.snapshot or not (sys.stdin.isatty() and sys.stdout.isatty()):
        print('\n'.join(line.rstrip() for line in render(data,width,height,error=error)))
        return
    import termios,tty
    original=termios.tcgetattr(sys.stdin);paused=False;mode='both';next_poll=time.monotonic()+1;previous=None
    def stop(signum,frame):raise KeyboardInterrupt
    old_signal=signal.signal(signal.SIGTERM,stop)
    try:
        tty.setcbreak(sys.stdin.fileno());sys.stdout.write('\x1b[?1049h\x1b[?25l');sys.stdout.flush()
        while True:
            size=shutil.get_terminal_size((104,32));width=args.width or size.columns;height=args.height or size.lines
            lines=render(data,max(1,width-1),height,mode,paused,error)
            # Cursor home + erase each row: no appended lines, no scrollback growth.
            if lines!=previous:
                header_height=len(logo(max(1,width-1)))
                for n,line in enumerate(lines):
                    tint='\x1b[36m' if n<header_height else '\x1b[32m' if n==header_height+1 and not error and not paused else '\x1b[33m' if n==len(lines)-1 or (n==header_height+1 and (error or paused)) else '\x1b[0m'
                    content=painted(line) if isinstance(line,Line) else tint+line+'\x1b[0m'
                    sys.stdout.write(f'\x1b[{n+1};1H\x1b[2K'+content)
                sys.stdout.flush();previous=lines
            ready,_,_=select.select([sys.stdin],[],[],.2)
            if ready:
                key=os.read(sys.stdin.fileno(),1)
                if key in (b'q',b'Q',b'\x03',b'\x04'):break
                if key==b' ':paused=not paused
                if key in (b'1',b'2',b'3'):mode={b'1':'both',b'2':'events',b'3':'cases'}[key]
            if not paused and time.monotonic()>=next_poll:
                try:data=json.loads(open(args.data_file).read()) if args.data_file else read_snapshot(args.database);error=None
                except (OSError,ValueError,sqlite3.Error):error=True
                next_poll=time.monotonic()+1;previous=None
    except KeyboardInterrupt:pass
    finally:
        termios.tcsetattr(sys.stdin,termios.TCSAFLUSH,original);signal.signal(signal.SIGTERM,old_signal)
        sys.stdout.write('\x1b[0m\x1b[?25h\x1b[?1049l');sys.stdout.flush()

if __name__=='__main__':main()
