#!/usr/bin/env python3
"""Root-only deployment backup and rollback. Incident data is never restored or removed."""
import argparse
import ast
import hashlib
import json
import os
import pathlib
import platform
import shutil
import subprocess
import time

ROOT=pathlib.Path('/var/lib/defense-agent-releases')
UNITS=('defense-agent','defense-agent-ai','defense-response','defense-executor','defense-alerts','aegis-target','aegis-target-broker')
FILES=('/etc/audit/plugins.d/defense-agent.conf','/etc/audit/rules.d/aegis-exec.rules','/etc/audit/rules.d/aegis-observe.rules','/etc/ssh/sshd_config.d/60-aegis-observability.conf')

def run(*args):
    return subprocess.run(args,capture_output=True,text=True,timeout=120)

def checked(*args):
    result=run(*args)
    if result.returncode:
        raise RuntimeError('Restore incomplete: '+' '.join(args)+' failed; inspect the host')
    return result

def reload_host(ssh_changed, audit_active):
    if shutil.which('augenrules'):checked('augenrules','--load')
    if audit_active:checked('service','auditd','restart')
    if ssh_changed and run('systemctl','is-active','ssh').returncode==0:
        checked('/usr/sbin/sshd','-t')
        checked('systemctl','reload','ssh')

def preflight():
    for source in pathlib.Path(__file__).parent.glob('*.py'):ast.parse(source.read_text(),filename=str(source))
    if platform.system()!='Linux':raise ValueError('Linux is required')
    release=dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID','').strip('"')!='ubuntu' or release.get('VERSION_ID','').strip('"')!='24.04':
        raise ValueError('This release supports Ubuntu 24.04; other distributions require validation')
    if platform.machine()!='x86_64' or pathlib.Path('/proc/1/comm').read_text().strip()!='systemd':
        raise ValueError('Validated platform requires x86_64 and systemd')
    if shutil.which('auditctl'):
        audit=run('auditctl','-s')
        if 'enabled 2' in audit.stdout:raise ValueError('Immutable audit policy requires administrator provisioning before installation')
    path=pathlib.Path('/etc/defense-agent/config.json')
    if path.exists():
        from policy import validate
        config=validate(json.loads(path.read_text()))
        from application_sources import sources
        from system_sources import discover
        sources(config);discover(config)
    if shutil.disk_usage('/var/lib').free < 512*1024*1024:raise ValueError('At least 512 MiB free space is required for deployment backup')

def managed(source):
    return [pathlib.Path(p) for p in ('/opt/defense-agent','/etc/defense-agent',*FILES,
        *sorted({'/etc/systemd/system/'+p.name for p in (source/'systemd').glob('*.service')} | {'/etc/systemd/system/defense-alerts.service'}))]

def fingerprint(path,include_directories=True):
    if path.is_symlink():raise ValueError('Managed paths must not be symlinks')
    if not path.exists():return None
    digest=hashlib.sha256()
    info=path.stat();digest.update(str((info.st_mode,info.st_uid,info.st_gid)).encode())
    files=sorted(path.rglob('*')) if path.is_dir() else [path]
    for item in files:
        if item.is_symlink():raise ValueError('Managed tree contains a symlink')
        if '__pycache__' in item.parts:continue
        if item.is_dir() and include_directories:
            info=item.stat();digest.update(b'DIR\0');digest.update(str(item.relative_to(path)).encode())
            digest.update(str((info.st_mode,info.st_uid,info.st_gid)).encode())
        elif item.is_file():
            info=item.stat();digest.update(str(item.relative_to(path) if item!=path else item.name).encode())
            digest.update(str((info.st_mode,info.st_uid,info.st_gid)).encode());digest.update(item.read_bytes())
    return digest.hexdigest()

def backup(source):
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    directory=ROOT/(str(time.time_ns()));directory.mkdir(mode=0o700)
    manifest={'fingerprint_version':2,'files':[],'services':{}}
    for index,path in enumerate(managed(source)):
        fingerprint(path)
        entry={'path':str(path),'backup':str(index),'exists':path.exists()}
        if path.exists():
            info=path.stat();entry.update(uid=info.st_uid,gid=info.st_gid,mode=info.st_mode&0o777)
            target=directory/str(index)
            if path.is_dir():shutil.copytree(path,target)
            else:shutil.copy2(path,target)
            entry['owners']={str(p.relative_to(path)):(p.stat().st_uid,p.stat().st_gid) for p in path.rglob('*')} if target.is_dir() else {}
        manifest['files'].append(entry)
    for unit in UNITS:
        manifest['services'][unit]={'active':run('systemctl','is-active',unit).returncode==0,'enabled':run('systemctl','is-enabled',unit).stdout.strip()=='enabled'}
    (directory/'manifest.json').write_text(json.dumps(manifest))
    return directory

def load(directory):
    directory=directory.resolve()
    if directory.parent!=ROOT.resolve() or not directory.name.isdigit():raise ValueError('Unknown release backup')
    return json.loads((directory/'manifest.json').read_text())

def fingerprint_options(manifest):
    version=manifest.get('fingerprint_version',1)
    if type(version) is not int or version not in (1,2):raise ValueError('Unknown release fingerprint version')
    return {'include_directories':version==2}

def seal(directory):
    manifest=load(directory)
    manifest['installed']={e['path']:fingerprint(pathlib.Path(e['path']),**fingerprint_options(manifest)) for e in manifest['files']}
    (directory/'manifest.json').write_text(json.dumps(manifest))

def restore(directory,failed=False):
    manifest=load(directory)
    ssh_path=pathlib.Path('/etc/ssh/sshd_config.d/60-aegis-observability.conf')
    ssh_before=fingerprint(ssh_path)
    audit_active=run('systemctl','is-active','auditd').returncode==0
    if not failed:
        if 'installed' not in manifest:raise ValueError('Incomplete deployment; use recover after inspecting installation failure')
        for path,expected in manifest['installed'].items():
            if fingerprint(pathlib.Path(path),**fingerprint_options(manifest))!=expected:raise ValueError('Managed files changed since installation; preserve operator changes before rollback')
    for unit in UNITS:
        if run('systemctl','is-active',unit).returncode==0 and run('systemctl','stop',unit).returncode:
            raise RuntimeError('Cannot safely stop '+unit)
    for entry in manifest['files']:
        path=pathlib.Path(entry['path']);saved=directory/entry['backup']
        if path.is_symlink():raise ValueError('Refusing to replace a symlink')
        if path.is_dir():shutil.rmtree(path)
        elif path.exists():path.unlink()
        if entry['exists']:
            path.parent.mkdir(parents=True,exist_ok=True)
            if saved.is_dir():shutil.copytree(saved,path)
            else:shutil.copy2(saved,path)
            os.chown(path,entry['uid'],entry['gid']);os.chmod(path,entry['mode'])
            for relative,owners in entry['owners'].items():os.chown(path/relative,*owners)
    checked('systemctl','daemon-reload')
    for unit,state in manifest['services'].items():
        enabled=run('systemctl','is-enabled',unit).stdout.strip()=='enabled'
        if enabled!=state['enabled']:checked('systemctl','enable' if state['enabled'] else 'disable',unit)
        if state['active']:checked('systemctl','start',unit)
    # Do not flush host audit policy. Removing loaded audit rules may require a reboot.
    reload_host(ssh_before!=fingerprint(ssh_path),audit_active)

def uninstall(directory):
    manifest=load(directory)
    ssh_path=pathlib.Path('/etc/ssh/sshd_config.d/60-aegis-observability.conf')
    ssh_before=fingerprint(ssh_path)
    audit_active=run('systemctl','is-active','auditd').returncode==0
    installed=manifest.get('installed')
    if not installed:raise ValueError('A sealed release backup is required')
    paths=[pathlib.Path(e['path']) for e in manifest['files'] if e['path']!='/etc/defense-agent']
    for path in paths:
        if fingerprint(path,**fingerprint_options(manifest))!=installed[str(path)]:raise ValueError('Managed files changed; inspect before uninstalling')
    for unit in UNITS:
        if run('systemctl','is-active',unit).returncode==0 and run('systemctl','stop',unit).returncode:raise RuntimeError('Cannot stop '+unit)
        if run('systemctl','is-enabled',unit).stdout.strip()=='enabled':checked('systemctl','disable',unit)
    for path in paths:
        if path.is_dir():shutil.rmtree(path)
        else:path.unlink(missing_ok=True)
    checked('systemctl','daemon-reload')
    reload_host(ssh_before!=fingerprint(ssh_path),audit_active)
    print('Agent removed. Configuration, incidents and rollback receipts retained. Loaded audit rules may remain until reboot; host firewall blocks retain their original expiry.')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('operation',choices=('check','backup','seal','rollback','recover','uninstall'));parser.add_argument('path',nargs='?');args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run as root')
    if args.operation=='check':preflight();print('PREFLIGHT PASSED')
    elif args.operation=='backup':print(backup(pathlib.Path(args.path)))
    elif args.operation=='seal':seal(pathlib.Path(args.path))
    elif args.operation=='uninstall':uninstall(pathlib.Path(args.path))
    else:restore(pathlib.Path(args.path),failed=args.operation=='recover');print('Release restored; incident data preserved. Review loaded audit rules before reboot.')

if __name__=='__main__':main()
