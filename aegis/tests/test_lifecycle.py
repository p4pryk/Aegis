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
    def test_nested_directories_and_broken_symlinks_are_checked(self):
        with tempfile.TemporaryDirectory() as root:
            root=pathlib.Path(root);child=root/'nested';child.mkdir();child.chmod(0o755)
            first=lifecycle.fingerprint(root);child.chmod(0o700)
            self.assertNotEqual(first,lifecycle.fingerprint(root))
            first=lifecycle.fingerprint(root);(root/'new-empty').mkdir()
            self.assertNotEqual(first,lifecycle.fingerprint(root))
            link=root/'broken';link.symlink_to(root/'does-not-exist')
            with self.assertRaises(ValueError):lifecycle.fingerprint(link)

    def test_rollback_refuses_nested_directory_edits_and_supports_old_manifests(self):
        import json
        with tempfile.TemporaryDirectory() as root:
            root=pathlib.Path(root);managed=root/'managed';managed.mkdir();child=managed/'nested';child.mkdir();child.chmod(0o755)
            (managed/'code.py').write_text('old');original_mode=child.stat().st_mode&0o777
            with patch.object(lifecycle,'ROOT',root/'backups'),patch.object(lifecycle,'managed',return_value=[managed]),patch.object(lifecycle,'UNITS',()),patch.object(lifecycle,'run'),patch.object(lifecycle.os,'chown'):
                backup=lifecycle.backup(root);(managed/'code.py').write_text('new');lifecycle.seal(backup)
                child.chmod(0o700)
                with self.assertRaisesRegex(ValueError,'changed'):lifecycle.restore(backup)
                self.assertEqual(child.stat().st_mode&0o777,0o700)
                child.chmod(original_mode);lifecycle.restore(backup)
                self.assertEqual((managed/'code.py').read_text(),'old')
                old=lifecycle.backup(root);manifest=json.loads((old/'manifest.json').read_text());manifest.pop('fingerprint_version')
                (old/'manifest.json').write_text(json.dumps(manifest))
                (managed/'code.py').write_text('current');lifecycle.seal(old);lifecycle.restore(old)
                self.assertEqual((managed/'code.py').read_text(),'old')
                manifest=json.loads((old/'manifest.json').read_text());manifest['fingerprint_version']=99;(old/'manifest.json').write_text(json.dumps(manifest))
                with self.assertRaisesRegex(ValueError,'Unknown release fingerprint version'):lifecycle.restore(old)
