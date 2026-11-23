import contextlib
import os
import pathlib
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import audit_spool


class AuditStreamEOF(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=pathlib.Path(self.tmp.name)
        self.config={'audit_spool_dir':str(root/'spool'),'runtime_dir':str(root/'run')}
        self.line=b'type=SYSCALL msg=audit(1700000000.000:123): success=yes pid=1 ppid=1 uid=0 key="lab_root_exec"'

    def forward(self,payload,patches=()):
        read_fd,write_fd=os.pipe()
        try:
            os.write(write_fd,payload)
        finally:
            os.close(write_fd)
        original=pathlib.Path.read_text
        def read_text(path,*args,**kwargs):
            if str(path)=='/proc/sys/kernel/random/boot_id':return 'test-boot'
            return original(path,*args,**kwargs)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(pathlib.Path,'read_text',read_text))
            for item in patches:stack.enter_context(item)
            with os.fdopen(read_fd,'rb') as stream:audit_spool.forward(self.config,stream)
        spool=audit_spool.Spool(self.config)
        self.addCleanup(spool.db.close)
        return spool

    def test_complete_lines_end_without_gap(self):
        spool=self.forward(self.line+b'\n')
        health=spool.health()
        self.assertEqual((health['accepted'],health['dropped'],health['stream_gaps']),(1,0,0))
        self.assertFalse(health['io_error_pending'])

    def test_incomplete_tail_is_a_persistent_gap_not_a_complete_record(self):
        spool=self.forward(self.line+b'\n'+self.line[:45])
        health=spool.health()
        self.assertEqual((health['accepted'],health['dropped'],health['stream_gaps']),(1,0,1))
        self.assertEqual(len(spool.batch(0)),1)
        reopened=audit_spool.Spool(self.config)
        try:self.assertEqual(reopened.health()['stream_gaps'],1)
        finally:reopened.db.close()

    def test_stream_read_and_poll_errors_are_persisted(self):
        for operation in ('read','select'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                root=pathlib.Path(tmp);self.config={'audit_spool_dir':str(root/'spool'),'runtime_dir':str(root/'run')}
                target=patch.object(audit_spool.os,'read',side_effect=OSError('read failed')) if operation=='read' else patch.object(audit_spool.select,'select',side_effect=OSError('poll failed'))
                with self.assertRaises(OSError):self.forward(self.line,patches=(target,))
                spool=audit_spool.Spool(self.config)
                try:self.assertEqual(spool.health()['stream_gaps'],1)
                finally:spool.db.close()

    def test_disk_failure_keeps_pending_marker_when_gap_cannot_be_persisted(self):
        failure=patch.object(audit_spool.Spool,'record_stream_gap',side_effect=sqlite3.OperationalError('disk full'))
        retry=patch.object(audit_spool,'persist_io_loss',return_value=False)
        spool=self.forward(self.line,patches=(failure,retry))
        self.assertTrue(spool.health()['io_error_pending'])
        self.assertTrue(audit_spool.persist_io_loss(spool))
        self.assertTrue(spool.health()['io_error_at'])
        self.assertFalse(spool.health()['io_error_pending'])


if __name__=='__main__':unittest.main()
