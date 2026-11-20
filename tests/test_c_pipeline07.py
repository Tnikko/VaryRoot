import json
import os
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile
from io import BytesIO

from tools.codeql07.runner import file_sha
from varyroot.c_pipeline import submit, verify_database
from varyroot.ledger import Ledger


class SourceArchive(unittest.TestCase):
    def test_matching_name_requires_matching_snapshot_bytes(self):
        import hashlib
        good = hashlib.sha256(b"original").hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_zip = BytesIO()
            with ZipFile(source_zip, "w") as sources:
                sources.writestr("src/"+good+".c", b"different")
            with ZipFile(root/"database.zip","w") as bundle:
                bundle.writestr("db/src.zip", source_zip.getvalue())
            with self.assertRaisesRegex(ValueError, "does not match"):
                verify_database(root, {"targets":[{"file_digest":good}]},
                                {"database_sha256":file_sha(root/"database.zip")})


@unittest.skipUnless(os.environ.get("VARYROOT_C07_SIGNED"),"requires real CodeQL acceptance ledger")
class PublishedCLI(unittest.TestCase):
    def test_restore_receipt_after_committed_freeze(self):
        # Simulate loss of the client's output directory after the production commit.
        store=Path(os.environ["VARYROOT_C07_SIGNED"])
        db=Ledger(store)
        run="pair.divergence"
        before=db.events(run)
        with tempfile.TemporaryDirectory() as tmp:
            result=submit(db,run,tmp,"unused","closed")
            self.assertEqual(result["state"],"frozen")
            self.assertEqual(json.loads((Path(tmp)/"receipt.json").read_bytes())["freeze_id"],result["freeze_id"])
            self.assertEqual(json.loads((Path(tmp)/"events.json").read_bytes()),before)
            self.assertEqual(db.events(run),before)
