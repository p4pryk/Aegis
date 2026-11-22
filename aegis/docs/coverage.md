# Linux coverage and validation matrix

This matrix describes the current implementation, not an assurance that a host emits all relevant events. Check Source Health and Coverage Check on each installation, configure producers and adapters, and verify representative events end to end. A quiet or readable source does not prove completeness.

| Source | Collected information | Requirements and boundaries |
| --- | --- | --- |
| Linux audit | Selected process executions, identity and selected persistence/configuration changes | `auditd`, enabled rules and working plugin; only watched paths and matching syscall filters are covered. Audit loss, missing events, nested mounts and unconfigured paths remain gaps. |
| SSH and system journal | SSH/PAM authentication and sessions; selected sudo, su, service, cron, kernel and security messages | Configured journal readers and supported formats; local event timestamps and session IDs provide evidence, not universal attribution. |
| System text logs | Selected auth/security and system messages | Supported auth and system files when file mode is selected. Rotation, permissions and parsing gaps must be monitored. |
| Service HTTP journal | Selected flat JSON, Nginx-like and Caddy-like access records, plus supported text access records | Explicit service units and matching formats; request context or IP alone does not prove exploitation and cannot authorize automatic containment. |
| Application files | Up to eight explicitly configured JSONL or standard access log files | The application must emit supported structured events; field mapping, ownership, permissions and correlation identifiers need verification. Session/request links remain application-reported. |
| Training application | Specific correlated authentication, account and persistence chains | Intentionally vulnerable lab only; its trusted broker and response path are not a generic production application adapter. |
| Database audit, container workloads, arbitrary application formats | Not generally collected or understood | Use supported exports with explicit mappings, or add and test a dedicated adapter. Host service logs alone do not establish coverage. |

| Host platform | Evidence and support boundary |
| --- | --- |
| Ubuntu 24.04 x86-64 with systemd | Current installer target; selected scenarios and a clean-host installation, update and rollback have been tested on Azure VMs. Long-duration acceptance remains a separate release gate. |
| Ubuntu 22.04 | Offline CI environment only; no installer/support claim without clean-host integration testing. |
| Debian, RHEL-family and other Linux | Some parser paths may be usable, but the installer and end-to-end behavior are not validated. Do not infer distribution support from unit tests or containers. |

A response is only considered when local policy and the available chain evidence authorize it. App logs, HTTP status, a shared IP and a model's statement alone are not proof that an attack succeeded. No product detects every suspicious activity; use independent monitoring and exercise the expected failure and attack paths for the actual host.
