"""Exercise the installer's actual configuration migration without changing the host."""
import json,pathlib,subprocess,sys,tempfile,unittest

class InstallProfile(unittest.TestCase):
    def migrate(self,config,demo):
        script=pathlib.Path(__file__).resolve().parents[1].joinpath('install.sh').read_text()
        source=script.split('python3 - "$demo" <<\'PY\'\n',1)[1].split('\nPY\n',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            path=pathlib.Path(directory)/'config.json';path.write_text(json.dumps(config))
            source=source.replace("'/etc/defense-agent/config.json'",repr(str(path)))
            subprocess.run([sys.executable,'-','true' if demo else 'false'],input=source,text=True,check=True)
            return json.loads(path.read_text())

    def test_agent_profile_removes_demo_preserves_custom_units_and_policy(self):
        config={'application_enabled':True,'web_units':['aegis-target.service','custom.service'],'application_units':['aegis-target.service'],
                'journal_units':['aegis-target.service','nginx.service'],'protected_users':['operator'],'ssh_response_users':['testuser']}
        result=self.migrate(config,False)
        self.assertFalse(result['application_enabled']);self.assertFalse(result['ssh_lab_users_enabled'])
        self.assertEqual(result['web_units'],['custom.service'])
        self.assertEqual(result['journal_units'],['nginx.service'])
        self.assertEqual(result['protected_users'],['operator'])
        self.assertEqual(result['ssh_response_users'],['testuser'])

    def test_demo_is_explicit_and_idempotent(self):
        result=self.migrate({'application_enabled':False},True)
        self.assertTrue(result['application_enabled'])
        self.assertEqual(result['application_units'],['aegis-target.service'])
        self.assertEqual(self.migrate(result,True),result)

    def test_agent_profile_preserves_custom_application_configuration(self):
        result=self.migrate({'application_units':['custom.service'],'application_enabled':True},False)
        self.assertTrue(result['application_enabled'])
        self.assertEqual(result['application_units'],['custom.service'])
