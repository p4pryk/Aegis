import pathlib,sys,tempfile,time,unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import agent,persistence


class ShellStartupTests(unittest.TestCase):
    def test_selected_shell_and_ssh_rc_paths_are_bounded(self):
        for path in ('/etc/environment','/etc/profile','/etc/profile.d/test.sh','/etc/zsh/zshenv','/etc/fish/conf.d/test.fish','/home/alice/.bash_login','/home/alice/.zshenv','/home/alice/.config/fish/config.fish','/home/alice/.config/fish/conf.d/test.fish','//root/.zlogin'):
            with self.subTest(path=path):self.assertEqual(persistence.scope(path),'shell_startup')
        for path in ('/root/.ssh/rc','/home/alice/.ssh/rc'):self.assertEqual(persistence.scope(path),'ssh_user_rc')
        for path in ('/etc/profile.d/readme.txt','/etc/fish/conf.d/nested/a.fish','/home/alice/work/.zshenv','/home/alice/.config/fish/conf.d/deep/a.fish','/home/alice/../bob/.zlogin','/tmp/.zshenv'):
            with self.subTest(path=path):self.assertIsNone(persistence.scope(path))

    def test_installer_paths_match_global_scope_and_root_startup_set(self):
        lines=(pathlib.Path(__file__).resolve().parents[1]/'install.sh').read_text().splitlines()
        global_line=next(line for line in lines if line.startswith('for path in /etc/environment '))
        paths=set(global_line.removeprefix('for path in ').removesuffix('; do').split())
        self.assertEqual(paths,set(persistence.GLOBAL_STARTUP_FILES+persistence.GLOBAL_STARTUP_DIRS))
        root_line=next(line for line in lines if line.startswith('for path in /root/.bashrc '))
        self.assertTrue({'/root/'+name for name in persistence.USER_STARTUP_FILES}<=set(root_line.split()))

    def test_startup_changes_remain_metadata_only_and_review_only(self):
        with tempfile.TemporaryDirectory() as directory:
            config=dict(agent.DEFAULTS,data_dir=directory,persistence_enabled=True);store=agent.Store(config)
            try:
                engine=agent.CorrelatedEngine(config,store,lambda _:self.fail('unexpected action'))
                for n,path in enumerate(('/etc/profile.d/aegis-test.sh','/home/alice/.config/fish/config.fish','/home/alice/.ssh/rc')):
                    stamp=time.time();serial=20000+n
                    for line in (f'type=SYSCALL msg=audit({stamp}:{serial}): success=yes pid=123 uid=1002 auid=1002 ses=42 exe="/usr/bin/touch" key="aegis_persistence"',f'type=PATH msg=audit({stamp}:{serial}): item=0 name="{path}" nametype=CREATE',f'type=EOE msg=audit({stamp}:{serial}):'):
                        engine.audit_line(line)
                    row=store.db.execute("SELECT id,kind,subject,version FROM cases WHERE kind='persistence_change' AND subject=?",(path,)).fetchone()
                    self.assertIsNotNone(row);self.assertFalse(engine.snapshot(*row)['allowed_actions']);self.assertFalse(persistence.lab_path(path))
            finally:store.db.close()
