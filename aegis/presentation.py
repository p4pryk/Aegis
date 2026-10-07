"""Read-only English labels and evidence-based display levels for both interfaces."""
import json

LEVELS={'neutral':('•','INFO'),'warning':('⚠','SUSPICIOUS'),'critical':('✖','ALERT'),'defended':('🛡︎','DEFENSE VERIFIED')}
STATES={'authorized':'Authorized activity — no response required','superseded':'Linked to a confirmed application case','collecting':'Collecting evidence','awaiting_analysis':'Assessment pending — response on hold','recognized':'Assessment recorded — response in progress or awaiting retry','defended':'Defense executed and verified','observing':'Monitoring — no response executed','insufficient_evidence':'Insufficient evidence — no response executed','analysis_error':'Assessment failed — no response executed','defense_error':'Defense failed or could not be verified','failed':'Response failed','executed':'Response executed','rejected':'Response rejected by policy'}
EVENTS={'persistence_change':'Persistence-related file changed; correlating the actor and application session.','app_persistence_job':'Application persistence operation recorded.','sql_auth_bypass':'SQL authentication bypass observed; collecting the subsequent application activity.','app_login':'Application authentication outcome recorded.','app_account_job':'Application account job completed; correlating independent kernel audit.','account_created':'Local account created; correlating evidence before any response.','process_exec':'Process execution recorded.','ssh_session_open':'SSH session opened and linked to its audit identity.','ssh_auth_failure':'SSH authentication failed. This alone does not authorize blocking.','ssh_login_success':'SSH authentication succeeded.','ssh_activity':'SSH connection or session event.','sudo_command':'Sudo command recorded and linked to the audit session.','sudo_auth_failure':'Sudo authentication failed. This alone does not authorize a response.','su_session_open':'User switch recorded and linked to the audit session.','su_auth_failure':'User-switch authentication failed. This alone does not authorize a response.','http_request':'HTTP request recorded; AEGIS links its request ID to application telemetry when available.','http_sqli_signature':'HTTP request matched an SQL-injection signature; success is unconfirmed.','service_event':'System service state or log event recorded.','sqli_signature':'SQL injection signature observed. Successful exploitation is not established.','http_allowed':'HTTP request accepted.','account_resolution_failed':'Account identity could not be resolved; response withheld.'}

def decode(value,fallback):
    try:return json.loads(value) if isinstance(value,str) else value or fallback
    except (ValueError,TypeError):return fallback

def badge(level,label=None):
    icon,default=LEVELS[level]
    return {'level':level,'icon':icon,'label':label or default}

def event_display(event):
    kind=event.get('kind','unknown')
    level='warning' if kind in ('ssh_auth_failure','sudo_auth_failure','su_auth_failure','sqli_signature','http_sqli_signature','sql_auth_bypass','app_account_job','persistence_change','app_persistence_job') else 'critical' if kind=='account_resolution_failed' else 'neutral'
    return {**badge(level,'SENSOR ERROR' if kind=='account_resolution_failed' else None),'message':EVENTS.get(kind,'Event recorded: '+str(kind))}

def action_display(result):
    action=result.get('action',{});kind=action.get('action');target=action.get('ip') or action.get('user') or action.get('path') or ''
    name={'quarantine_account':'Account quarantine','terminate_session':'Session termination','block_ip':'IP block','revoke_app_session':'Application session revocation','quarantine_persistence':'Persistence quarantine'}.get(kind,str(kind or 'Response'))
    if kind=='terminate_session':target=str(target)+' / session '+str(action.get('session','—'))
    verified=result.get('status')=='executed' and result.get('result',{}).get('verified') is True
    level='defended' if verified else 'critical' if result.get('status') in ('failed','executed') else 'warning'
    return {**badge(level,'VERIFIED' if verified else 'FAILED / UNVERIFIED' if level=='critical' else 'PENDING'),'message':name+(' · '+str(target) if target else '')}

def case_display(case):
    status=case.get('status');analysis=decode(case.get('analysis_json'),{});evidence=decode(case.get('evidence_json'),{});results=decode(case.get('result_json'),[])
    if not isinstance(analysis,dict):analysis={}
    if not isinstance(evidence,dict):evidence={}
    if status in ('analysis_error','defense_error'):view=badge('critical','ASSESSMENT ERROR' if status=='analysis_error' else 'DEFENSE ERROR')
    elif status=='defended':
        verified=isinstance(results,list) and bool(results) and all(isinstance(r,dict) and r.get('status')=='executed' and r.get('result',{}).get('verified') is True for r in results)
        view=badge('defended') if verified else badge('critical','UNVERIFIED RESPONSE')
    elif status in ('authorized','superseded'):view=badge('neutral','AUTHORIZED' if status=='authorized' else 'LINKED CASE')
    elif analysis.get('attack') is True:
        confirmed=bool(evidence.get('allowed_actions')) and any('not_causal' not in e.get('relation','not_causal') for e in evidence.get('edges',[])) and analysis.get('confidence',0)>=.85
        view=badge('critical','POLICY VIOLATION' if confirmed else 'SUSPICIOUS') if confirmed else badge('warning')
    elif case.get('kind') in ('ssh_threshold','waf_threshold','app_sql_login','application_shell','persistence_change') or status in ('collecting','awaiting_analysis'):view=badge('warning','ASSESSMENT PENDING' if status in ('collecting','awaiting_analysis') else 'SUSPICIOUS ACTIVITY')
    else:view=badge('neutral','MONITORING')
    # Preserve original evidence and narratives; do not present a translation as an AI assessment.
    archived=bool(analysis.get('summary')) and analysis.get('language')!='en'
    summary=analysis.get('summary') if not archived else 'Historical assessment recorded. The original narrative is retained in the local evidence archive.'
    kind_label={'ssh_threshold':'SSH authentication activity','waf_threshold':'Suspicious HTTP requests','ssh_session_account':'SSH account change','web_shell_account':'Account creation','app_sql_login':'SQL authentication bypass','app_sql_account':'SQL injection account chain','app_sql_persistence':'SQL injection persistence chain','persistence_change':'Persistence file change','application_shell':'Application shell launch'}.get(case.get('kind'),'Incident')
    return {**view,'kind_label':kind_label,'status_label':STATES.get(status,str(status or 'Unknown status')),'summary':summary or 'Assessment pending. Automatic response is on hold.','archived_original':archived,'uncertainty':analysis.get('uncertainty','') if not archived else '', 'origin_label':'Local policy assessment' if analysis.get('origin')=='local-authorization-policy' else 'Model assessment'}
