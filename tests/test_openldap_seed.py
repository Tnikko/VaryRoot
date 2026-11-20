import unittest
from varyroot.source_seed import grants


class OpenLdapCatalogTests(unittest.TestCase):
    def test_approved_real_source_catalog_has_fixed_inputs(self):
        paths = {
            "proposal.json": "seed",
            "before-canonical.tar.gz": "source",
            "after-canonical.tar.gz": "source",
            "openldap-include.tar.gz": "contract",
            "ubuntu24-libc-headers.tar.gz": "source",
            "curl_config_openldap.h": "source",
            "contract.json": "contract",
            "source-lock.json": "contract",
            "getattr.c": "contract",
            "openldap_role.py": "source",
        }
        files = [dict(ref=name + "@1", path=name, kind=kind, sha256="0" * 64, size=1)
                 for name, kind in paths.items()]
        catalog = dict(schema_version=1, seed="curl-openldap-npd-2018", adapter="openldap_real_v1", files=files)
        self.assertEqual({item.path for item in grants(catalog)}, set(paths))
        with self.assertRaises(ValueError):
            grants(dict(catalog, adapter="unregistered"))
        with self.assertRaises(ValueError):
            grants(dict(catalog, files=files[:-1]))


class AstAdapterTests(unittest.TestCase):
    def test_ast_adapter_exports_structural_analysis(self):
        from varyroot.openldap_role import analyze_tree
        self.assertTrue(callable(analyze_tree))


class RealRoleReplayTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").environ.get("VARYROOT_REAL_OPENLDAP_CATALOG"), "locked catalog not supplied")
    def test_same_whitelisted_source_produces_identical_seed_bytes(self):
        import json
        import tempfile
        from pathlib import Path
        from varyroot.sandbox import Input, Scope, materialize, run_role, resolve_image
        catalog_path = Path(__import__("os").environ["VARYROOT_REAL_OPENLDAP_CATALOG"])
        catalog = json.loads(catalog_path.read_bytes())
        items = [Input(**row) for row in catalog["files"]]
        image = resolve_image("varyroot-agent-a:step04")
        outputs = []
        with tempfile.TemporaryDirectory(dir=catalog_path.parent.parent) as temp:
            for index in range(2):
                attempt = Path(temp) / ("attempt-" + str(index))
                scope = Scope("replay:curl", catalog["seed"], "development", 0,
                              "A", "seed", "same-request", "try-" + str(index))
                materialize(attempt, catalog_path.parent, scope, items)
                result = run_role(attempt, ["python", "/input/openldap_role.py"],
                                  image=image, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append((attempt / "output/seed.json").read_bytes())
        self.assertEqual(outputs[0], outputs[1])
        packet = json.loads(outputs[0])
        self.assertEqual(packet["state"], "seed_pending")
        self.assertEqual(packet["blockers"],
                         ["A4_before_missing", "A4_after_missing", "A6_candidate_check_missing"])
        for side, chain, direct in (("before", ["bvp", "&bvals"], False),
                                    ("after", ["&bvals"], True)):
            ast = packet["frontend"][side]["ast"]
            self.assertEqual(ast["output_calls"][0]["chain"], chain)
            self.assertEqual(ast["output_calls"][1]["chain"], chain)
            self.assertEqual(ast["direct_loop_condition"], direct)
            target = [row for row in ast["access_inventory"] if row["target"]]
            self.assertEqual(len(target), 1)
            self.assertEqual(target[0]["text"], "bvals[i].bv_val")
            self.assertTrue(any(row["text"] == "bv.bv_val"
                                for row in ast["access_inventory"]))
            self.assertEqual(packet["frontend"][side]["compile"]["compiler"],
                             "Ubuntu clang version 18.1.3 (1ubuntu1)")
        self.assertEqual(packet["contract_pending_negative_test"]["outcome"], "uncovered")
        self.assertEqual(packet["separation_probes"]["checked_log_continue"],
                         {"H_check": "quiet", "H_path": "report", "H_loop": "report"})
        self.assertEqual(packet["separation_probes"]["goto_cleanup"],
                         {"H_check": "quiet", "H_path": "quiet", "H_loop": "uncovered"})



class ProductionGateTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").environ.get("VARYROOT_REAL_OPENLDAP_CATALOG"), "locked catalog not supplied")
    def test_real_coordinator_stops_without_a4_a6(self):
        import tempfile
        from pathlib import Path
        from varyroot.source_seed import prepare_seed
        from varyroot.ledger import Ledger, LedgerError
        catalog = Path(__import__("os").environ["VARYROOT_REAL_OPENLDAP_CATALOG"])
        with tempfile.TemporaryDirectory(dir=catalog.parent.parent) as workspace:
            run = "integration:curl-openldap-pending"
            result = prepare_seed(workspace, catalog, run)
            self.assertEqual(result["state"], "seed_pending")
            db = Ledger(workspace)
            gate = db.seed_gate(run)
            self.assertTrue({"before_ok", "after_ok", "candidates_ok"} <=
                            set(gate["blockers"]))
            with self.assertRaisesRegex(LedgerError, "seed gate blocked"):
                db.accept_seed(run, db.run(run)["version"], 1)
            self.assertEqual(db.run(run)["state"], "seed_pending")


class PendingContractTests(unittest.TestCase):
    @unittest.skipUnless(__import__("os").environ.get("VARYROOT_REAL_OPENLDAP_CATALOG"), "locked catalog not supplied")
    def test_unapproved_reference_contract_yields_pending_seed(self):
        import hashlib
        import json
        import shutil
        import tempfile
        from pathlib import Path
        from varyroot.sandbox import Input, Scope, materialize, run_role, resolve_image
        catalog_path = Path(__import__("os").environ["VARYROOT_REAL_OPENLDAP_CATALOG"])
        original = json.loads(catalog_path.read_bytes())
        with tempfile.TemporaryDirectory(dir=catalog_path.parent.parent) as temp:
            root = Path(temp)
            for row in original["files"]:
                shutil.copyfile(catalog_path.parent / row["path"], root / row["path"])
            contract_path = root / "contract.json"
            contract = json.loads(contract_path.read_bytes())
            contract["approval_status"] = "pending"
            contract_path.write_text(json.dumps(contract, sort_keys=True))
            for row in original["files"]:
                if row["path"] == "contract.json":
                    raw = contract_path.read_bytes()
                    row["sha256"] = hashlib.sha256(raw).hexdigest()
                    row["size"] = len(raw)
            attempt = root / "attempt"
            scope = Scope("pending:curl", original["seed"], "development", 0,
                          "A", "seed", "contract-pending", "attempt-1")
            materialize(attempt, root, scope, [Input(**row) for row in original["files"]])
            result = run_role(attempt, ["python", "/input/openldap_role.py"],
                              image=resolve_image("varyroot-agent-a:step04"), timeout=120)
            self.assertEqual(result.returncode, 0, result.stderr)
            packet = json.loads((attempt / "output/seed.json").read_bytes())
            self.assertEqual(packet["state"], "seed_pending")
            self.assertTrue(all(result["outcome"] == "uncovered"
                                for candidate in packet["candidates"]
                                for result in candidate["predictions"].values()))


if __name__ == "__main__":
    unittest.main()
