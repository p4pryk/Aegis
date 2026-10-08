"""Read-only explanation of recorded evidence; never recomputes response permissions."""
import datetime
import json


def decode(value,default):
    try:return json.loads(value) if isinstance(value,str) else value or default
    except (ValueError,TypeError):return default


def timeline(case):
    evidence=decode(case.get('evidence_json'),{});analysis=decode(case.get('analysis_json'),{})
    events=sorted(evidence.get('events',[]),key=lambda e:(e['event_time'],e['event_id']))
    numbers={e['event_id']:n for n,e in enumerate(events,1)}
    allowed=evidence.get('allowed_actions',[]);policy=evidence.get('policy',{})
    lines=[('CASE '+case['id']+' / version '+str(case.get('version',0)),'neutral'),
           ('RECORDED FACTS — chronological; attribution is not proof of malicious intent','neutral')]
    if len(events)>=(64 if case.get('kind')=='host_change' else 256):
        lines.append(('Case event limit reached: this view may omit additional telemetry.','warning'))
    if not events:lines.append(('Evidence snapshot not yet available.','warning'))
    for event in events:
        d=event.get('details',{})
        source=d.get('source') or ('journald' if event['kind'] in ('sudo_command','sudo_auth_failure','su_session_open','su_auth_failure','http_request','http_sqli_signature','service_event') else 'application' if event['kind'].startswith('app_') else 'sshd journal' if event['kind']=='ssh_failure' else 'auditd')
        stamp=datetime.datetime.fromtimestamp(event['event_time'],datetime.timezone.utc).isoformat(timespec='milliseconds')
        label=d.get('path') or d.get('exe') or event['subject']
        lines.append((f"#{numbers[event['event_id']]} {stamp} [{source}] {event['kind']}: {label}",'neutral'))
        fields=('user','actor','target_user','command','op','acct','grp','id','new_uid','new_gid','old_uid','old_gid','pid','ppid','start_ticks','parent_start_ticks','boot_id','audit_session','session','auid','uid','operation','mechanism','request_id')
        context=' | '.join(k+'='+str(d[k]) for k in fields if d.get(k) is not None and not (k=='session' and event['kind'].startswith('app_')))
        if context:lines.append(('  '+context,'neutral'))
        if event['kind'] in ('identity_change','security_file_change','persistence_change') and not d.get('start_ticks'):
            lines.append(('  Process birth identity unavailable; PID alone cannot establish a process link.','warning'))
        if d.get('audited_inode'):lines.append(('  Inode metadata at audit time (not a before/after diff): '+json.dumps(d['audited_inode'],sort_keys=True),'neutral'))
    lines.append(('EVIDENCE LINKS','neutral'))
    linked=set()
    for edge in evidence.get('edges',[]):
        start,end=edge.get('from'),edge.get('to')
        if start not in numbers or end not in numbers:continue
        relation=edge.get('relation','unknown');linked.update((start,end))
        strength='ATTRIBUTION' if relation=='exact_audit_session_attribution_not_causal' else 'CONTEXT ONLY' if 'not_causal' in relation else 'VERIFIED LINK'
        lines.append((f"#{numbers[start]} -> #{numbers[end]} [{strength}] "+relation.replace('_',' '),'warning' if strength=='CONTEXT ONLY' else 'neutral'))
    if not evidence.get('edges'):lines.append(('No recorded links. Proximity or a shared IP does not establish a chain.','warning'))
    unlinked=[str(numbers[e['event_id']]) for e in events if e['event_id'] not in linked]
    if unlinked:lines.append(('Events without a recorded link: '+', '.join('#'+n for n in unlinked),'warning'))
    lines.append(('DECISION / RESPONSE GATE','neutral'))
    status=case.get('status')
    if status=='collecting':reason='Collecting: the last snapshot may be outdated; awaiting a new assessment.'
    elif policy.get('actor_authorization')=='approved':reason='Local policy marks this actor as approved; no response is authorized.'
    elif not allowed:reason='No response authorized by local policy. Attribution alone does not prove compromise.'
    else:reason='Local policy supplied '+str(len(allowed))+' permitted actions; assessment, freshness and target checks still gate execution.'
    lines.append((reason,'neutral' if allowed else 'warning'))
    if not allowed:
        requirements={'ssh_threshold':'Missing: a linked malicious consequence; failed logins alone do not permit blocking.',
                      'waf_threshold':'Missing: proof of successful exploitation and a linked consequence.',
                      'app_sql_login':'Missing: a kernel-confirmed consequence linked to the bypassed application session.',
                      'ssh_session_account':'Check: audited SSH identity, matching root account-creation process, target identity and configured response scope.',
                      'web_shell_account':'Check: complete kernel process lineage, matching account producer and configured response scope.'}
        lines.append((requirements.get(case.get('kind'),'Review-only evidence: no automatic containment rule for this standalone change.'),'warning'))
    if analysis:
        local=analysis.get('origin')=='local-authorization-policy'
        lines.append(('LOCAL ASSESSMENT' if local else 'MODEL ASSESSMENT — confidence is not a calibrated probability','neutral'))
        if not local:lines.append(('Attack assessment: '+str(analysis.get('attack'))+' | confidence score: '+str(analysis.get('confidence','unavailable')),'neutral'))
        for label,key in (('Description','summary'),('Uncertainty','uncertainty'),('Next step','next_step')):
            if analysis.get(key):lines.append((label+': '+analysis[key],'neutral'))
    else:lines.append(('Assessment pending; no model verdict recorded.','warning'))
    lines.append(('Recorded state: '+str(status),'neutral'))
    for action in decode(case.get('result_json'),[]):
        if not isinstance(action,dict):continue
        from presentation import action_display
        view=action_display(action);lines.append((view['message']+' / '+view['label'],view['level']))
    return lines
