#!/bin/bash
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo 'Run as root' >&2; exit 1; }
demo=false
case "${1:-}" in
  '') ;;
  --demo) demo=true ;;
  *) echo 'Usage: install.sh [--demo]' >&2; exit 1 ;;
esac
[ "$#" -le 1 ] || { echo 'Usage: install.sh [--demo]' >&2; exit 1; }
source_dir=$(cd -- "$(dirname -- "$0")" && pwd)
python3 "$source_dir/lifecycle.py" check
release_backup=$(python3 "$source_dir/lifecycle.py" backup "$source_dir")
trap 'echo "Installation failed; restoring prior managed files" >&2; python3 "$source_dir/lifecycle.py" recover "$release_backup"' ERR
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq auditd audispd-plugins nftables python3 cron
getent group defense-ai >/dev/null || groupadd --system defense-ai
id defense-ai >/dev/null 2>&1 || useradd --system --gid defense-ai --home-dir /var/lib/defense-agent-ai --shell /usr/sbin/nologin defense-ai
if $demo; then
  getent passwd aegis-target >/dev/null || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin aegis-target
fi
systemctl disable --now defense-alerts.service 2>/dev/null || true
rm -f /opt/defense-agent/notifications.py /opt/defense-agent/__pycache__/notifications.*.pyc /etc/systemd/system/defense-alerts.service
systemctl stop defense-executor.service defense-response.service defense-agent-ai.service defense-agent.service 2>/dev/null || true
install -d -m 0700 /var/lib/defense-agent-audit
install -d -m 0755 /opt/defense-agent
install -d -m 0750 -o root -g defense-ai /var/lib/defense-agent
install -d -m 0750 -o defense-ai -g defense-ai /var/lib/defense-agent-ai
if $demo; then install -d -m 0700 /var/lib/aegis-target; fi
install -d -m 0750 -o root -g defense-ai /etc/defense-agent
install -d -m 0750 /var/log/defense-agent
install -d -m 0700 /root/.ssh
for name in doctor.py release_check.py history_context.py lifecycle.py policy.py coverage_check.py queue_view.py application_sources.py system_sources.py file_logs.py response_view.py rollback.py incident_view.py telemetry.py audit_spool.py monitoring.py maintenance.py response.py journal_stream.py agent.py ai_worker.py app_correlation.py journal_sources.py persistence.py console.py presentation.py; do
  install -m 0755 "$source_dir/$name" /opt/defense-agent/
done
if [ ! -f /etc/defense-agent/config.json ]; then
  cat > /etc/defense-agent/config.json <<'JSON'
{"mode":"correlated","web_units":[],"application_units":[],"journal_comms":["sudo","su","su-l"],"journal_identifiers":["sudo","su","systemd"],"journal_units":["nginx.service","apache2.service","httpd.service"],"application_enabled":false,"persistence_enabled":true,"protected_users":["root","labadmin"],"protected_ips":[],"block_seconds":600,"ssh_lab_users_enabled":false,"ssh_response_users":[],"ssh_account_creator_allowlist":["root","labadmin"],"ssh_dedicated_source_ips":[],"app_dedicated_source_ips":[],"analysis_timeout_seconds":90}
JSON
fi
python3 - "$demo" <<'PY'
import json,pathlib,sys
p=pathlib.Path('/etc/defense-agent/config.json');config=json.loads(p.read_text());demo=sys.argv[1]=='true'
for key in ('web_units','application_units','journal_units'):
    units=[u for u in config.get(key,[]) if u!='aegis-target.service']
    config[key]=list(dict.fromkeys(units+(['aegis-target.service'] if demo else [])))
config['ssh_lab_users_enabled']=demo
config['lab_response_enabled']=demo
config['trust_account_creators']=demo
config.setdefault('response_mode','enforce' if demo else 'observe')
config.setdefault('response_users',[])
config.setdefault('protected_groups',['sudo','wheel','adm'])
if demo:config['application_enabled']=True
elif not config['application_units']:config['application_enabled']=False
p.write_text(json.dumps(config)+'\n')
PY
if $demo; then
  install -m 0755 "$source_dir/vulnerable_app.py" /opt/defense-agent/
else
  systemctl disable --now aegis-target.service aegis-target-broker.service 2>/dev/null || true
  rm -f /opt/defense-agent/vulnerable_app.py /opt/defense-agent/__pycache__/vulnerable_app.*.pyc
  rm -f /etc/systemd/system/aegis-target.service /etc/systemd/system/aegis-target-broker.service
fi

chmod 0600 /etc/defense-agent/config.json
if [ -f /etc/defense-agent/ai.json ]; then
  chown root:defense-ai /etc/defense-agent/ai.json
  chmod 0640 /etc/defense-agent/ai.json
fi
# Trusted, root-owned sensor input; never truncate existing evidence.
touch /var/log/defense-agent/application.jsonl
chown root:root /var/log/defense-agent/application.jsonl
chmod 0600 /var/log/defense-agent/application.jsonl
install -m 0644 "$source_dir/systemd"/defense-*.service /etc/systemd/system/
if $demo; then install -m 0644 "$source_dir/systemd"/aegis-target*.service /etc/systemd/system/; fi
cat > /opt/defense-agent/audit-forward <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/defense-agent/agent.py audit-plugin
EOF
chmod 0755 /opt/defense-agent/audit-forward
cat > /etc/audit/plugins.d/defense-agent.conf <<'EOF'
active = yes
direction = out
path = /opt/defense-agent/audit-forward
type = always
format = string
EOF
if ! grep -Rq -- 'lab_root_exec' /etc/audit/rules.d; then
  printf '%s\n' '-a always,exit -F arch=b64 -S execve,execveat -F euid=0 -k lab_root_exec' > /etc/audit/rules.d/aegis-exec.rules
fi
cat > /etc/audit/rules.d/aegis-observe.rules <<EOF
-a always,exit -F arch=b64 -S execve,execveat -F auid>=1000 -F auid!=4294967295 -F euid!=0 -k aegis_session_exec
-w /etc/passwd -p wa -k aegis_identity
-w /etc/shadow -p wa -k aegis_identity
-w /etc/group -p wa -k aegis_identity
-w /etc/gshadow -p wa -k aegis_identity
-w /etc/sudoers -p wa -k aegis_identity
-w /etc/sudoers.d -p wa -k aegis_identity
-w /etc/crontab -p wa -k aegis_persistence
-w /etc/cron.d -p wa -k aegis_persistence
-w /etc/systemd/system -p wa -k aegis_persistence
-w /home -p wa -k aegis_persistence
-w /root/.ssh -p wa -k aegis_persistence
EOF
for path in /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/pam.d /etc/security/access.conf; do
  [ ! -e "$path" ] || printf '%s\n' "-w $path -p wa -k aegis_identity" >> /etc/audit/rules.d/aegis-observe.rules
done
if $demo; then
  printf '%s\n' "-a always,exit -F arch=b64 -S execve,execveat -F euid=$(id -u aegis-target) -k aegis_app_exec" >> /etc/audit/rules.d/aegis-observe.rules
fi
for path in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron/crontabs; do
  [ ! -d "$path" ] || printf '%s\n' "-w $path -p wa -k aegis_persistence" >> /etc/audit/rules.d/aegis-observe.rules
done
# Preserve the existing administrator's access while making SSH failures observable.
if [ -x /usr/sbin/sshd ]; then
printf '%s\n' 'LogLevel VERBOSE' > /etc/ssh/sshd_config.d/60-aegis-observability.conf
/usr/sbin/sshd -t
systemctl reload ssh
fi
augenrules --load
systemctl disable --now defense-agent-dashboard.service defense-lab-gateway.service 2>/dev/null || true
# One-time conversion enables bounded incremental space reclamation.
python3 - <<'PYDB'
import sqlite3,pathlib
path=pathlib.Path('/var/lib/defense-agent/incidents.db')
if path.exists():
    with sqlite3.connect(path) as db:
        if db.execute('PRAGMA auto_vacuum').fetchone()[0]!=2:
            db.execute('PRAGMA auto_vacuum=INCREMENTAL');db.execute('VACUUM')
PYDB
health_started=$(date +%s)
systemctl daemon-reload
systemctl enable --now defense-response.service defense-executor.service defense-agent.service defense-agent-ai.service
systemctl restart defense-response.service defense-executor.service defense-agent.service defense-agent-ai.service
if $demo; then
  systemctl enable --now aegis-target-broker.service aegis-target.service
  systemctl restart aegis-target-broker.service aegis-target.service
fi
service auditd restart

python3 - "$health_started" <<'HEALTH'
import json,sqlite3,subprocess,sys,time
started=int(sys.argv[1]);deadline=time.monotonic()+30
while time.monotonic()<deadline:
    try:
        with sqlite3.connect('file:/var/lib/defense-agent/incidents.db?mode=ro',uri=True,timeout=2) as db:
            row=db.execute("SELECT value FROM state WHERE key='heartbeat'").fetchone()
            health=json.loads(row[0]) if row else {}
        pid=int(subprocess.check_output(['systemctl','show','--property=MainPID','--value','defense-agent'],text=True))
        if pid>0 and health.get('pid')==pid and health.get('time',0)>=started and time.time()-health['time']<10:break
    except (OSError,ValueError,sqlite3.Error):pass
    time.sleep(1)
else:raise SystemExit('Collector health did not recover after installation')
HEALTH
python3 "$source_dir/lifecycle.py" seal "$release_backup"
trap - ERR
printf 'Release backup: %s\n' "$release_backup"
