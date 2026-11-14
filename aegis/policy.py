"""Explicit containment scope; detection is independent of response permissions."""
import ipaddress
import grp
import pwd
import re

MODES = ('observe', 'review', 'enforce')

def validate(config):
    if config.get('response_mode', 'observe') not in MODES:
        raise ValueError('response_mode must be observe, review or enforce')
    for key in ('response_users', 'protected_users', 'protected_groups', 'ssh_response_users'):
        values = config.get(key, [])
        if not isinstance(values, list) or len(values) > 256 or any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.@-]{0,63}', v) for v in values):
            raise ValueError('Invalid '+key)
    for key in ('lab_response_enabled','trust_account_creators','auto_access_logs','service_warnings_enabled'):
        if key in config and type(config[key]) is not bool:raise ValueError(key+' must be boolean')
    if not isinstance(config.get('protected_ips',[]),list):raise ValueError('protected_ips must be a list')
    for address in config.get('protected_ips',[]):ipaddress.ip_network(address,strict=False)
    if type(config.get('incident_context_seconds',3600)) is not int or not 120<=config.get('incident_context_seconds',3600)<=3600:
        raise ValueError('incident_context_seconds must be 120–3600')
    mapping=config.get('web_context_units',{})
    unit=lambda value:isinstance(value,str) and bool(re.fullmatch(r'[A-Za-z0-9_.@:-]{1,120}\.service',value))
    if not isinstance(mapping,dict) or len(mapping)>32 or any(not unit(name) or not isinstance(values,list) or len(values)>16 or any(not unit(value) for value in values) for name,values in mapping.items()):
        raise ValueError('Invalid web_context_units')
    return config

def account_allowed(name, config):
    if name == 'root' or name in config.get('protected_users', []):
        return False
    scoped = name in config.get('response_users', []) or (config.get('lab_response_enabled', False) and bool(re.fullmatch(r'lab_[a-z0-9_]{1,24}', name)))
    if not scoped:
        return False
    try:
        account = pwd.getpwnam(name)
        if account.pw_uid < 1000 or account.pw_uid == 65534:
            return False
        for group in config.get('protected_groups', ['sudo', 'wheel', 'adm']):
            try: entry = grp.getgrnam(group)
            except KeyError: continue
            if account.pw_gid == entry.gr_gid or name in entry.gr_mem:
                return False
    except KeyError:
        return False
    return True

def require_enforce(config):
    if config.get('response_mode', 'observe') != 'enforce':
        raise ValueError('Containment disabled by response mode')
