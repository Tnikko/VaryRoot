"""An exported container rootfs may contain absolute in-container symlinks."""
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.namespace.import_rootfs import extract_verified


class NamespaceImportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, members):
        path = self.root / "rootfs.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, kind, value in members:
                info = tarfile.TarInfo(name)
                if kind == "link":
                    info.type = tarfile.SYMTYPE
                    info.linkname = value
                    tar.addfile(info)
                else:
                    data = value.encode()
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
        return path

    def test_absolute_container_symlink_is_preserved(self):
        archive = self.archive([("usr/bin/tool", "file", "ok"),
                                ("etc/alternatives/tool", "link", "/usr/bin/tool")])
        extract_verified(archive, self.root / "out")
        self.assertEqual((self.root / "out/usr/bin/tool").read_text(), "ok")
        self.assertEqual((self.root / "out/etc/alternatives/tool").readlink().as_posix(),
                         "/usr/bin/tool")

    def test_member_under_absolute_symlink_is_rejected(self):
        archive = self.archive([("escape", "link", "/tmp"),
                                ("escape/bad", "file", "bad")])
        with self.assertRaisesRegex(ValueError, "symlink parent"):
            extract_verified(archive, self.root / "out")

    def test_duplicate_archive_path_is_rejected_before_extraction(self):
        archive = self.archive([("same", "file", "one"),
                                ("same", "file", "two")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            extract_verified(archive, self.root / "out")
        self.assertFalse((self.root / "out").exists())
