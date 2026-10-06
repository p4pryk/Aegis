"""Bounded parsers for selected journald sources; raw messages never leave this module."""
import ipaddress
import json
import pathlib
import re

SAFE = re.compile(r'[A-Za-z0-9_.@:-]{1,128}')
ACCESS = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]{3,10}) (\S+) HTTP/[0-9.]+" ([0-9]{3}) (?:\d+|-)')
SQLI = re.compile(r"(?i)(?:union(?:\s|%20|\+)+select|(?:%27|')\s*(?:or|and)(?:\s|%20|\+)+|(?:--|%2d%2d)|sleep(?:%28|\())")


def command(config):
    selectors = []
    for field, values in (
        ('_COMM', config.get('journal_comms', [])),
        ('SYSLOG_IDENTIFIER', config.get('journal_identifiers', [])),
        ('_SYSTEMD_UNIT', config.get('journal_units', [])),
    ):
        if not isinstance(values, list):
            continue
        for value in values[:32]:
            if isinstance(value, str) and SAFE.fullmatch(value):
                selectors.append(f'{field}={value}')
    args = ['journalctl', '--follow', '--since=10 minutes ago', '--output=json']
    for i, selector in enumerate(selectors):
        if i:
            args.append('+')
        args.append(selector)
    return args if selectors else None


def parse(record, boot_id, config):
    comm = str(record.get('_COMM', ''))
    ident = str(record.get('SYSLOG_IDENTIFIER', ''))
    unit = str(record.get('_SYSTEMD_UNIT', ''))
    units = config.get('journal_units', [])
    if not isinstance(units, list):
        units = []
    msg = str(record.get('MESSAGE', ''))[:8192]
    cursor = str(record.get('__CURSOR', ''))[:512]
    try:
        stamp = int(record['__REALTIME_TIMESTAMP']) / 1_000_000
    except (KeyError, TypeError, ValueError):
        return None

    audit_session = record.get('_AUDIT_SESSION')
    auid = record.get('_AUDIT_LOGINUID')
    audit_session = str(audit_session) if str(audit_session).isdigit() else None
    auid = str(auid) if str(auid).isdigit() else None
    try:
        pid = int(record.get('_PID'))
    except (TypeError, ValueError):
        pid = None
    priority = str(record.get('PRIORITY', ''))
    common = {'boot_id': boot_id, 'audit_session': audit_session, 'auid': auid,
              'pid': pid, 'unit': unit or None, 'source': unit or ident or comm or 'journal',
              'priority': priority or None}

    kind = subject = description = None
    details = dict(common)
    if comm in ('sudo',) or ident == 'sudo':
        actor = re.match(r'^(?:sudo:\s*)?([A-Za-z0-9_.-]{1,32})\s*:', msg)
        target = re.search(r'\bUSER=([A-Za-z0-9_.-]{1,32})', msg)
        command_match = re.search(r'\bCOMMAND=(\S+)', msg)
        failed = re.search(r'(?i)(authentication failure|incorrect password|auth could not identify)', msg)
        user_match = re.search(r'\buser=([A-Za-z0-9_.-]{1,32})', msg)
        details.update(actor=(actor[1] if actor else user_match[1] if user_match else None),
                       target_user=target[1] if target else None,
                       command=pathlib.PurePosixPath(command_match[1]).name[:80] if command_match else None)
        if failed:
            kind, description = 'sudo_auth_failure', 'Sudo authentication failure recorded; no response authorized.'
        elif command_match:
            kind, description = 'sudo_command', 'Sudo command recorded; correlating the audit session.'
        else:
            return None
        subject = f'{boot_id}:{audit_session}:{auid}' if audit_session and auid else details['actor'] or 'sudo'
    elif comm in ('su', 'su-l') or ident == 'su':
        opened = re.search(r'session opened for user ([A-Za-z0-9_.-]{1,32}) by ([A-Za-z0-9_.-]{1,32})\(uid=(\d+)\)', msg)
        failed = re.search(r'(?i)(authentication failure|failed to execute|auth could not identify)', msg)
        if opened:
            kind, description = 'su_session_open', 'User switch opened; correlating the audit session.'
            details.update(target_user=opened[1], actor=opened[2], actor_uid=opened[3])
        elif failed:
            kind, description = 'su_auth_failure', 'User-switch authentication failure recorded; no response authorized.'
            target = re.search(r'\buser=([A-Za-z0-9_.-]{1,32})', msg)
            details.update(target_user=target[1] if target else None)
        else:
            return None
        subject = f'{boot_id}:{audit_session}:{auid}' if audit_session and auid else details.get('actor') or 'su'
    elif unit in units:
        access = None
        if unit == 'aegis-target.service':
            try:
                structured = json.loads(msg)
            except (TypeError, ValueError):
                structured = {}
            if not isinstance(structured, dict):
                structured = {}
            if structured.get('event') == 'aegis_http_access':
                try:
                    ip = str(ipaddress.ip_address(structured['ip']))
                    status = structured['status']
                    method = structured['method']
                    path = structured['path']
                    request_id = structured['request_id']
                    if type(status) is not int or not 100 <= status <= 599 or not isinstance(path, str) or not re.fullmatch(r'[A-Z]{3,10}', method) or not re.fullmatch(r'[a-f0-9]{32}', request_id):
                        return None
                    details.update(ip=ip, method=method, path=path.split('?', 1)[0].split('#', 1)[0][:256], status=status, request_id=request_id)
                    kind, subject = 'http_request', ip
                    description = 'HTTP request recorded with its application request ID.'
                except (KeyError, TypeError, ValueError):
                    return None
        if kind is None:
            access = ACCESS.match(msg)
        if access:
            try:
                ip = str(ipaddress.ip_address(access[1]))
            except ValueError:
                return None
            target = access[3]
            path = target.split('?', 1)[0].split('#', 1)[0][:256]
            details.update(ip=ip, method=access[2], path=path, status=int(access[4]))
            if SQLI.search(target):
                kind, description = 'http_sqli_signature', 'HTTP request matched a SQL-injection signature; success is unconfirmed.'
            else:
                kind, description = 'http_request', 'HTTP access record received from a monitored service.'
            subject = ip
        elif kind is None:
            kind, subject = 'service_event', unit
            details['category'] = 'error' if priority.isdigit() and int(priority) <= 3 else 'service log'
            description = 'Monitored service log metadata recorded; message content was not retained.'
    elif ident == 'systemd':
        transition = re.search(r'\b(Starting|Started|Stopping|Stopped|Failed to start|Scheduled restart job for) ([A-Za-z0-9_.@:-]+\.service)\b', msg)
        if not transition:
            return None
        kind, subject = 'service_event', transition[2]
        details.update(unit=transition[2], category=transition[1].lower())
        description = 'System service state change recorded.'
    else:
        return None

    if not cursor:
        cursor = f'{stamp}:{pid}:{kind}:{subject}'
    event_id = 'journal:' + cursor
    return {'event_id': event_id, 'event_time': stamp, 'kind': kind, 'subject': subject,
            'details': details, 'description': description}
