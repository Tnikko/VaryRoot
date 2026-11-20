import json
import os
import tempfile
import unittest
from pathlib import Path
from varyroot.qualification import qualify
from varyroot.seed_fixture import bind_fixture
from varyroot.ledger import Ledger

@unittest.skipUnless(os.environ.get("VARYROOT_R07_DOCKER")=="1","requires isolated verifier image")
class Qualification(unittest.TestCase):
    def test_npd_seed(self):
        with tempfile.TemporaryDirectory() as folder:
            db=Ledger(folder)
            bind_fixture(db,"npd","exit")
            result=qualify(db,"npd")
            self.assertEqual(result["state"],"seed_accepted")
            self.assertEqual(db.run("npd")["state"],"seed_accepted")
            self.assertEqual(db.balances("npd")["B.verify"],2)
