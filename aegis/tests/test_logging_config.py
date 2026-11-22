import pathlib,sys,tempfile,time,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,persistence


class LoggingConfigurationTests(unittest.TestCase):
    def test_installer_and_parser_use_same_logging_watch_paths(self):
        script=(pathlib.Path(__file__).resolve().parents[1]/'install.sh').read_text()
        line=next(line for line in script.splitlines() if line.startswith('for path in /etc/audit/auditd.conf '))
        self.assertEqual(set(line.removeprefix('for path in ').removesuffix('; do').split()),set(persistence.LOG_CONFIG_FILES+persistence.LOG_CONFIG_DIRS))

    def test_scope_covers_selected_config_but_not_unrelated_paths(self):
        for path in ('/etc/audit/auditd.conf','//etc/audit/rules.d/example.rules','/etc/audit/plugins.d/example.conf','/etc/systemd/journald.conf','/etc/systemd/journald.conf.d/custom.conf','/etc/rsyslog.conf','/etc/rsyslog.d/example.conf'):
            with self.subTest(path=path):self.assertEqual(persistence.watched_path(path),'security_logging_configuration')
        for path in ('/etc/audit/rules.d/../secret','/etc/audit-other/rules.d/a','/var/log/audit/audit.log','/etc/systemd/system/sshd.service'):
            with self.subTest(path=path):self.assertNotEqual(persistence.watched_path(path),'security_logging_configuration')

    def test_audit_record_creates_metadata_only_review_case(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory,persistence_enabled=True);store=agent.Store(config)
            try:
                engine=agent.CorrelatedEngine(config,store,lambda _:self.fail('unexpected action'));stamp=time.time();path='/etc/audit/rules.d/aegis-fixture.conf'
                for line in (f'type=SYSCALL msg=audit({stamp}:701): success=yes pid=123 uid=0 auid=1002 ses=42 exe="/usr/bin/touch" key="aegis_identity"',f'type=PATH msg=audit({stamp}:701): item=0 name="{path}" nametype=CREATE',f'type=EOE msg=audit({stamp}:701):'):
                    engine.audit_line(line)
                row=store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='host_change'").fetchone();evidence=engine.snapshot(*row)
                self.assertEqual(evidence['events'][0]['details']['mechanism'],'security_logging_configuration')
                self.assertEqual(evidence['allowed_actions'],[])
            finally:store.db.close()
