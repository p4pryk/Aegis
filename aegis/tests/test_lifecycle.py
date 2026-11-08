import pathlib
import tempfile
import unittest
from unittest.mock import patch
import lifecycle

class Lifecycle(unittest.TestCase):
    def test_fingerprint_detects_changes_and_refuses_symlinks(self):
        with tempfile.TemporaryDirectory() as root:
            directory=pathlib.Path(root);path=directory/'module.py';path.write_text('first')
            first=lifecycle.fingerprint(directory);path.write_text('second')
            self.assertNotEqual(first,lifecycle.fingerprint(directory))
            link=directory/'link';link.symlink_to(path)
            with self.assertRaises(ValueError):lifecycle.fingerprint(directory)
    def test_backup_restores_managed_files_and_refuses_operator_conflict(self):
        with tempfile.TemporaryDirectory() as root:
            root=pathlib.Path(root);managed=root/'managed';managed.mkdir();(managed/'code.py').write_text('old')
            with patch.object(lifecycle,'ROOT',root/'backups'),patch.object(lifecycle,'managed',return_value=[managed]),patch.object(lifecycle,'UNITS',()),patch.object(lifecycle,'run'),patch.object(lifecycle.os,'chown'):
                backup=lifecycle.backup(root);(managed/'code.py').write_text('new');lifecycle.seal(backup)
                (managed/'code.py').write_text('operator edit')
                with self.assertRaisesRegex(ValueError,'changed'):lifecycle.restore(backup)
                (managed/'code.py').write_text('new');lifecycle.restore(backup)
                self.assertEqual((managed/'code.py').read_text(),'old')
