"""Offline regression against previously archived, never model generated sources."""

import os
import unittest
from pathlib import Path

from varyroot.b_clang_receipt import clang_ast, clang_cfg, make_receipt


ROOT = Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs"))


class RealSourceReceiptTest(unittest.TestCase):
    @unittest.skipUnless((ROOT / "step4f-oob-feasibility/source/parent/src/dissectors/ec_vnc.c").exists(),
                         "archived Ettercap source unavailable")
    def test_ettercap_oob_patch(self):
        root = ROOT / "step4f-oob-feasibility"
        trees, texts = [], []
        for side in ("parent", "fixed"):
            path = root / "source" / side / "src/dissectors/ec_vnc.c"
            argv = ["clang-18", "-Dlib_ettercap_EXPORTS",
                    "-I" + str(root / "build" / (side + "-final") / "include"),
                    "-I" + str(root / "source" / side / "include"),
                    "-I" + str(root / "qlinclude"), "-c", str(path), "-o", str(path) + ".o"]
            tree, status = clang_ast(argv, str(root), "dissector_vnc")
            self.assertEqual(status["exit_code"], 0, status)
            self.assertIsNotNone(tree, status)
            cfg, cfg_status = clang_cfg(argv, str(root), "dissector_vnc")
            self.assertEqual(cfg_status["exit_code"], 0, cfg_status)
            self.assertTrue(cfg["blocks"], cfg_status)
            trees.append(tree)
            texts.append(path.read_text())
        receipt = make_receipt(*texts, *trees, (184, 187), "memcpy(buffer, ptr, 16)")
        self.assertEqual(receipt["target_binding"], "exact_1to1", receipt)
        self.assertEqual(len(receipt["edit_groups"]), 1, receipt)
        self.assertEqual(receipt["edit_groups"][0]["roles"], ["guard"])

    @unittest.skipUnless((ROOT / "step4d-execution/worktree/runs/step4d-directed-v3/curl-probe-v1/before/source/lib/openldap.c").exists(),
                         "archived OpenLDAP source unavailable")
    def test_openldap_npd_patch(self):
        root = ROOT / "step4d-execution/worktree/runs/step4d-directed-v3/curl-probe-v1"
        trees, texts = [], []
        for side in ("before", "after"):
            source = root / side / "source"
            path = source / "lib/openldap.c"
            argv = ["clang-18", "-std=gnu17", "-O0", "-DHAVE_CONFIG_H",
                    "-I" + str(source / "lib"), "-I" + str(source / "include"),
                    "-I" + str(root / "ldap-headers/include"),
                    "-c", str(path), "-o", str(path) + ".o"]
            tree, status = clang_ast(argv, str(source), "ldap_recv")
            self.assertEqual(status["exit_code"], 0, status)
            self.assertIsNotNone(tree, status)
            cfg, cfg_status = clang_cfg(argv, str(source), "ldap_recv")
            self.assertEqual(cfg_status["exit_code"], 0, cfg_status)
            self.assertTrue(cfg["blocks"], cfg_status)
            trees.append(tree)
            texts.append(path.read_text())
        receipt = make_receipt(*texts, *trees, (550, 550), "bvals[i].bv_val",
                               contract_calls=("ldap_get_attribute_ber",))
        self.assertEqual(receipt["target_binding"], "exact_1to1", receipt)
        self.assertGreaterEqual(len(receipt["edit_groups"]), 1)


if __name__ == "__main__":
    unittest.main()
