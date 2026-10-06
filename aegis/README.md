# AEGIS — Defense Agent

A Linux VM agent that groups security events, asks a model to describe each attack chain, and executes only actions authorized by local policy. Its continuously refreshing interface runs in a terminal. Runtime Python code uses the standard library.

This repository includes a deliberately vulnerable training target. Use it only on an isolated VM. Keep its port 8081 closed in the cloud firewall and reach it through an SSH tunnel. Credentials, SSH keys, VM logs and case data are excluded from this directory.

## What it sees

- SSH failures and audited sessions, root process launches, and new Linux accounts.
- Process launches under the training application service, including a shell.
- Changes to `authorized_keys` under `/home` or `/root/.ssh`, files in `/etc/cron.d`, `/etc/crontab`, and service files under `/etc/systemd/system`.
- The training application's SQL authentication results and subsequent account or persistence operations.

The agent builds cases with explicit links. A shared IP or close timestamp is context, not proof. The model receives one bounded case and selects IDs from a root-generated action catalog. Root rechecks current evidence and target identity before acting. For a confirmed SQLi-to-account chain, the default response is account quarantine and revocation of that app session. For a confirmed SQLi-to-training-persistence chain, it quarantines the exact file and revokes the session. IP blocking requires a separately enrolled dedicated source and a complete account chain. A shell launch or file change alone is described without an automatic destructive action.

The training SQL query is genuinely vulnerable. Bounded account creation and persistence are separate HTTP operations, not arbitrary SQLite remote code execution. The test account has no password or home directory. Training cron files run `/usr/bin/true`; training service files run `/usr/bin/sleep 600`. Only files under the `lab_aegis_` or `lab-aegis-` prefixes can be automatically quarantined. Their bytes are preserved in `/var/lib/defense-agent/quarantine/`.

## Install on isolated Ubuntu 24.04

The VM needs systemd, auditd, nftables, Python 3, SSH access and an identity permitted to invoke an existing model deployment. The tested setup uses Azure managed identity and `gpt-6-luna`. Place the endpoint and deployment settings in `/etc/defense-agent/ai.json` using [ai.json.example](ai.json.example). Set `protected_ips` in `/etc/defense-agent/config.json` to include the administrator and VM addresses before enrolling any IP for automatic blocking. `install.sh` creates a default config when one does not exist.

Run `sudo ./install.sh` and then `./watch.sh` on the VM. `./watch.sh --snapshot` prints one screen. The running services are `defense-agent`, `defense-executor`, `defense-agent-ai`, `aegis-target-broker`, and `aegis-target`. The console only reads SQLite; closing it does not stop detection.

Forward workstation port 18091 through SSH to the VM's localhost:8081. Submit `POST /login` with JSON `{"username":"admin' --","password":"incorrect"}`. The response contains a short-lived `session`. Submit `POST /accounts` with `{"session":"...","user":"lab_http_example"}`, or `POST /persistence` with `{"session":"...","artifact":"cron","name":"example"}`. `POST /shell` with that session runs a fixed harmless command under the unprivileged app account. Use a fresh artifact name per test. Synthetic correct credentials appear on the target's `GET /` page. AEGIS itself has no web UI.

## Validation

Run `python3 -m unittest discover -s tests -q`. The `live-app-tests.py`, `live-persistence-tests.py`, `live-session-tests.py`, and `live-firewall-tests.py` scripts exercise real kernel audit, model assessment and firewall behavior on the isolated VM. Run them as root, one at a time. They create temporary network namespaces and clean up their test users, files and rules. Case history remains available for review.

Default bounds are 40 model calls per hour, at least eight seconds between call starts, two seconds of quiet before case analysis, 90 seconds for a model result, ten minutes of correlation evidence, and 2000 recent console observations. Missing evidence or unavailable analysis withholds automatic defense. These limits are not a latency guarantee. Production use needs off-VM evidence retention, log rotation, sensor-loss alerting, load measurements and hardening of the privileged training broker.
