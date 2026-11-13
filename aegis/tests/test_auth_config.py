import pathlib,sys,tempfile,time,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,persistence

class AuthConfigurationTests(unittest.TestCase):
    def test_bounded_paths(self):
        for path in ('/etc/ssh/sshd_config','/etc/ssh/sshd_config.d','/etc/ssh/sshd_config.d/50-test.conf','/etc/pam.d','/etc/pam.d/sshd','/etc/security/access.conf'):
            with self.subTest(path=path):self.assertEqual(persistence.watched_path(path),'authentication_configuration')
        for path in ('/etc/ssh/ssh_host_rsa_key','/etc/ssh/sshd_config.d/../ssh_host_rsa_key','/etc/security/limits.conf','/etc/pam.d-other/test'):
            with self.subTest(path=path):self.assertNotEqual(persistence.watched_path(path),'authentication_configuration')

    def test_audited_auth_changes_are_observations_only(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory,protected_ips=[],persistence_enabled=True)
            store=agent.Store(config);engine=agent.CorrelatedEngine(config,store,lambda _:self.fail('unexpected action'))
            try:
                for i,path in enumerate(('/etc/ssh/sshd_config','/etc/ssh/sshd_config.d/test.conf','/etc/pam.d/sshd','/etc/security/access.conf')):
                    stamp=time.time();serial=38000+i;pid=7321
                    lines=[f'type=SYSCALL msg=audit({stamp}:{serial}): success=yes pid={pid} ppid=1 uid=0 auid=1000 ses=99 exe="/usr/bin/test" key="aegis_identity"',f'type=PATH msg=audit({stamp}:{serial}): item=0 name="{path}" inode=1 nametype=NORMAL',f'type=EOE msg=audit({stamp}:{serial}):']
                    with patch.object(agent,'process_snapshot',return_value={'pid':pid,'start_ticks':123}):
                        for line in lines:engine.audit_line(line)
                rows=store.db.execute("SELECT subject,details_json FROM correlation_events WHERE kind='security_file_change'").fetchall()
                self.assertEqual(len(rows),4)
                for path,details in rows:
                    self.assertIn('authentication_configuration',details)
                    self.assertNotIn('fixture_secret',details)
                case=store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='host_change'").fetchone()
                self.assertIsNotNone(case)
                self.assertEqual(engine.snapshot(*case)['allowed_actions'],[])
            finally:store.db.close()

if __name__=='__main__':unittest.main()
