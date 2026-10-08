"""Metadata-only host changes and bounded, exact audit-session enrichment."""
import json
import re
import time

CHANGES=('identity_change','security_file_change','persistence_change')
CONTEXT=(*CHANGES,'sudo_command','sudo_auth_failure','su_session_open','su_auth_failure','service_event','process_exec')
RECORDS={'USER_CHAUTHTOK','1108','GRP_CHAUTHTOK','1133','CHUSER_ID','1125','ACCT_LOCK','1135','ACCT_UNLOCK','1136','USER_MGMT','1102','GRP_MGMT','1132','ADD_GROUP','1116','DEL_GROUP','1117','CHGRP_ID','1119','DEL_USER','1115'}


def identity(details):
    session=str(details.get('audit_session',details.get('session','')))
    auid=str(details.get('auid',''))
    if not session.isdigit() or not auid.isdigit() or not 0<=int(session)<4294967295 or not 0<=int(auid)<4294967295 or not details.get('boot_id'):return None
    return details['boot_id'],session,auid


def management(engine,kind,content,event_id,stamp,fields):
    if kind not in RECORDS or fields.get('uid')!='0':return
    payload=content.split('msg=',1)[-1]
    if not re.search(r'\bres=success\b',payload):return
    # Never retain raw records, password hashes, command arguments or key contents.
    values={k:v.strip('"')[:128] for k,v in re.findall(r'\b(op|acct|grp|exe|id|new_gid|new_uid|old_gid|old_uid)=("[^"]*"|[^\s\x27]+)',payload)}
    operation=re.search(r'\bop=(.*?)(?=\s+\w+=|$)',payload)
    if operation:values['op']=operation[1].strip("\"'")[:128]
    pid=int(fields['pid']);snap=engine.audit_snapshot(pid) or {}
    details=dict(values,boot_id=engine.boot_id,session=fields.get('ses'),auid=fields.get('auid'),pid=pid,start_ticks=snap.get('start_ticks'),source='auditd',record_type=kind)
    event=engine.normalize('identity_change',values.get('acct') or values.get('grp') or values.get('op','identity'),details,event_id+':'+kind,stamp)
    if engine.remember(event):
        engine.store.observe('auditd',event['kind'],event['subject'],'Successful identity/group change recorded; authorization is not inferred.',event['event_id'],stamp)
        # Unset audit sessions are grouped by boot, not falsely attributed to a user.
        subject=':'.join(identity(details) or (engine.boot_id,'unattributed'))
        engine.create_or_append('host_change',subject,event)


def session_events(engine,login,until):
    ident=identity(login['details'])
    if ident is None:return []
    rows=engine.db.execute('SELECT event_id,event_time,kind,subject,details_json FROM correlation_events WHERE kind IN ('+','.join('?' for _ in CONTEXT)+') AND event_time BETWEEN ? AND ? ORDER BY event_time DESC LIMIT 2048',
                           (*CONTEXT,max(login['event_time'],until-600),until)).fetchall()
    result=[]
    for eid,stamp,kind,subject,raw in rows:
        details=json.loads(raw)
        if identity(details)==ident:result.append(engine.normalize(kind,subject,details,eid,stamp))
        if len(result)>=32:break
    return result



def enrich(engine,now):
    # Revisit after batched intake: delayed journal/audit records and restarts can fill gaps.
    if now-getattr(engine,'last_telemetry_enrichment',0)<1:return
    engine.last_telemetry_enrichment=now
    rows=engine.db.execute("SELECT id,kind,subject FROM cases WHERE kind IN ('host_change','persistence_change','ssh_session_account') AND created_at>? AND status NOT IN ('defended','recognized','defense_error','superseded')",(now-600,)).fetchall()
    for identifier,kind,subject in rows:
        events=engine.events(identifier)
        anchor=next((e for e in events if e['kind'] in (*CHANGES,'account_created')),None)
        if not anchor:continue
        ident=identity(anchor['details'])
        if ident is None or ident[0]!=engine.boot_id:continue
        row=engine.db.execute('SELECT event_id,event_time,details_json FROM ssh_sessions WHERE identity=?',(':'.join(ident),)).fetchone()
        if not row or row[1]>anchor['event_time']:continue
        login=engine.normalize('ssh_session_open',':'.join(ident),json.loads(row[2]),row[0],row[1])
        # A bounded window around the change; identical IP/user in another session never joins.
        until=min(now,anchor['event_time']+600)
        extra=session_events(engine,login,until)
        engine.create_or_append(kind,subject,anchor,[login,*extra],case_id=identifier)


def links(events):
    edges=[]
    for login in (e for e in events if e['kind']=='ssh_session_open'):
        ident=identity(login['details'])
        if ident is None:continue
        for event in events:
            if event['kind'] in CONTEXT and identity(event['details'])==ident and 0<=event['event_time']-login['event_time']<=600:
                edges.append({'from':login['event_id'],'to':event['event_id'],'relation':'exact_audit_session_attribution_not_causal'})
    for change in (e for e in events if e['kind'] in CHANGES):
        d=change['details']
        if not d.get('start_ticks') or not d.get('pid'):continue
        for process in (e for e in events if e['kind']=='process_exec'):
            p=process['details']
            if all(p.get(k)==d.get(k) for k in ('boot_id','pid','start_ticks','session','auid')) and p.get('boot_id') and 0<=change['event_time']-process['event_time']<=600:
                edges.append({'from':process['event_id'],'to':change['event_id'],'relation':'same_boot_pid_start_ticks_and_audit_identity'})
    return edges
