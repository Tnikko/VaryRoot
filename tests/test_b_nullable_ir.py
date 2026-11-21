"""Generic nullable output static facts on a simple API and locked real source."""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from varyroot.b_clang_receipt import clang_ast, clang_cfg
from varyroot.b_nullable_ir import (extract_nullable_facts, predict_nullable,
                                    make_nullable_pair, make_nullable_inspector)
from varyroot.b_factor_gate import classify
from varyroot.b_prompt import strip_source_comments
from varyroot.b_static_retry import apply_local_patch


@unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
class NullableIRTest(unittest.TestCase):
    def test_simple_api_distinguishes_check_from_block(self):
        template = ("int acquire(int **out);\n"
                    "int parse(void) {\n  int *slot=0; int rc=acquire(&slot);\n"
                    "  if (rc == 0) {\n    REWRITE\n    return slot[0];\n  }\n  return 0;\n}\n")
        config = {"target_expression": "slot[0]", "slot_expr": "slot",
                  "success_expr": "rc == 0", "target_call": "acquire"}
        cases = (("", (False, False)),
                 ("if (slot == 0) { }", (True, False)),
                 ("if (slot == 0) return 0;", (True, True)),
                 ("if (slot != 0) { return slot[0]; }", None))
        with tempfile.TemporaryDirectory() as folder:
            for index, (rewrite, expected) in enumerate(cases[:3]):
                source = template.replace("REWRITE", rewrite)
                path = Path(folder) / f"case-{index}.c"
                path.write_text(source)
                argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                ast, status = clang_ast(argv, folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                cfg, status = clang_cfg(argv, folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                facts = extract_nullable_facts(source, ast, cfg, 6, config)
                self.assertEqual((facts["check_seen"], facts["blocked"]), expected)
                self.assertEqual(predict_nullable(facts),
                                 ("quiet" if expected[0] else "report",
                                  "quiet" if expected[1] else "report"))

    @unittest.skipUnless((Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs")) /
                          "step3-model-intake/out/proposal-input.json").exists(),
                         "archived OpenLDAP skeleton unavailable")
    def test_locked_openldap_skeleton_parent_and_fixed(self):
        runs = Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs"))
        headers = Path("/tmp/varyroot-blind-headers")
        self.assertTrue((headers / "ldap/include/ldap.h").exists())
        sources = json.loads((runs / "step3-model-intake/out/proposal-input.json").read_text())["skeletons"]
        config = {"target_expression": "bvals[i].bv_val", "slot_expr": "bvals",
                  "success_expr": "rc == LDAP_SUCCESS", "target_call": "ldap_get_attribute_ber"}
        with tempfile.TemporaryDirectory() as folder:
            for side, expected in (("before", (False, False)), ("after", (True, True))):
                source = sources[side]
                path = Path(folder) / (side + ".c")
                path.write_text(source)
                argv = ["clang-18", "--no-default-config", "--target=x86_64-pc-linux-gnu",
                        "-x", "c", "-std=gnu17", "-I" + str(headers / "ldap/include"),
                        "-isystem", str(headers / "sys/usr/include/x86_64-linux-gnu"),
                        "-isystem", str(headers / "sys/usr/include"),
                        "-c", str(path), "-o", str(path) + ".o"]
                ast, status = clang_ast(argv, folder, "ldap_recv_slice")
                self.assertEqual(status["exit_code"], 0, status)
                cfg, status = clang_cfg(argv, folder, "ldap_recv_slice")
                self.assertEqual(status["exit_code"], 0, status)
                line = next(i for i, text in enumerate(source.splitlines(), 1)
                            if "bvals[i].bv_val" in text)
                facts = extract_nullable_facts(source, ast, cfg, line, config)
                self.assertEqual((facts["check_seen"], facts["blocked"]), expected, facts)

    @unittest.skipUnless((Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs")) /
                          "step3-model-intake/out/proposal-input.json").exists(),
                         "archived OpenLDAP skeleton unavailable")
    def test_real_skeleton_inspector_admits_single_static_check(self):
        runs = Path(os.environ.get("VARYROOT_RUNS", "/home/tq/varyroot/runs"))
        sources = json.loads((runs / "step3-model-intake/out/proposal-input.json").read_text())["skeletons"]
        headers = Path("/tmp/varyroot-blind-headers")
        config = {"target_expression": "bvals[i].bv_val", "slot_expr": "bvals",
                  "success_expr": "rc == LDAP_SUCCESS", "target_call": "ldap_get_attribute_ber"}
        with tempfile.TemporaryDirectory() as folder:
            serial = 0
            def compile_source(source):
                nonlocal serial
                serial += 1
                path = Path(folder) / f"candidate-{serial}.c"
                path.write_text(source)
                argv = ["clang-18", "--no-default-config", "--target=x86_64-pc-linux-gnu",
                        "-x", "c", "-std=gnu17", "-I" + str(headers / "ldap/include"),
                        "-isystem", str(headers / "sys/usr/include/x86_64-linux-gnu"),
                        "-isystem", str(headers / "sys/usr/include"),
                        "-c", str(path), "-o", str(path) + ".o"]
                ast, status = clang_ast(argv, folder, "ldap_recv_slice")
                self.assertEqual(status["exit_code"], 0, status)
                cfg, status = clang_cfg(argv, folder, "ldap_recv_slice")
                self.assertEqual(status["exit_code"], 0, status)
                return ast, cfg
            before_ast, _ = compile_source(sources["before"])
            after_ast, _ = compile_source(sources["after"])
            target_lines = {side: next(i for i, text in enumerate(source.splitlines(), 1)
                                       if "bvals[i].bv_val" in text)
                            for side, source in sources.items()}
            inspector = make_nullable_inspector(make_nullable_pair("real_static", "slot"), config,
                {"before": (sources["before"], before_ast, target_lines["before"]),
                 "after": (sources["after"], after_ast, target_lines["after"])}, compile_source)
            candidate, reason = apply_local_patch(strip_source_comments(sources["before"]),
                "    for(i = 0;", "    if (bvals != NULL) { }\n    for(i = 0;")
            self.assertIsNone(reason)
            inspected = inspector(candidate, "before")
            self.assertEqual(classify(inspected["clang_receipt"])["status"], "admitted",
                             inspected["clang_receipt"])
            self.assertEqual(inspected["predictions"], ("quiet", "report"))


if __name__ == "__main__":
    unittest.main()
