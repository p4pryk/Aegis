import pathlib,sys,types,unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import lab_cleanup


class LabCleanupTests(unittest.TestCase):
    def test_rejects_unrelated_accounts_and_unexpected_identity(self):
        with patch.object(lab_cleanup.subprocess,'run') as run:
            with self.assertRaises(ValueError):lab_cleanup.remove_test_user('root')
            with patch.object(lab_cleanup.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=0,pw_dir='/root')):
                with self.assertRaises(ValueError):lab_cleanup.remove_test_user('lab_tel_123456789')
            run.assert_not_called()

    def test_retries_until_test_account_disappears(self):
        account=types.SimpleNamespace(pw_uid=1234,pw_dir='/home/lab_tel_123456789')
        with patch.object(lab_cleanup.pwd,'getpwnam',side_effect=[account,account,account,account,KeyError]), \
             patch.object(lab_cleanup.subprocess,'run',return_value=types.SimpleNamespace(stderr='busy')) as run, \
             patch.object(lab_cleanup.time,'sleep'),patch.object(lab_cleanup.os.path,'lexists',return_value=False):
            lab_cleanup.remove_test_user('lab_tel_123456789')
        self.assertEqual([call.args[0][0] for call in run.call_args_list],['pkill','userdel','pkill','userdel'])

    def test_reports_a_remaining_home(self):
        with patch.object(lab_cleanup.pwd,'getpwnam',side_effect=KeyError),patch.object(lab_cleanup.os.path,'lexists',return_value=True):
            with self.assertRaises(RuntimeError):lab_cleanup.remove_test_user('lab_up_12345678')

    def test_does_not_touch_an_account_with_changed_uid(self):
        first=types.SimpleNamespace(pw_uid=1234,pw_dir='/home/lab_up_12345678')
        changed=types.SimpleNamespace(pw_uid=1235,pw_dir=first.pw_dir)
        with patch.object(lab_cleanup.pwd,'getpwnam',side_effect=[first,changed]),patch.object(lab_cleanup.subprocess,'run') as run:
            with self.assertRaises(ValueError):lab_cleanup.remove_test_user('lab_up_12345678')
            run.assert_not_called()
