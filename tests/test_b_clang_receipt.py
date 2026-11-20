import shutil
import tempfile
import unittest
from pathlib import Path

from varyroot.b_clang_receipt import clang_ast, clang_cfg, make_receipt
from varyroot.b_factor_gate import classify


BEFORE = """int parse(int x) {
  if (x < 0) return 0;
  return x;
}
"""
AFTER = """int parse(int x) {
  if (x < 0) goto cleanup;
  return x;
cleanup:
  return 0;
}
"""


class ClangReceiptTest(unittest.TestCase):
    def test_target_line_without_matching_ast_expression_is_unproven(self):
        source = "int parse(int x) {\n  return x;\n}\n"
        fake = {"kind": "FunctionDecl", "inner": [
            {"kind": "CompoundStmt", "range": {"begin": {"line": 2}}}]}
        receipt = make_receipt(source, source, fake, fake,
                               (2, 2), "return x;")
        self.assertEqual(receipt["target_binding"], "unproven")

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_goto_and_exclusive_label_form_one_region(self):
        with tempfile.TemporaryDirectory() as folder:
            trees = []
            for side, source in (("before", BEFORE), ("after", AFTER)):
                path = Path(folder) / (side + ".c")
                path.write_text(source)
                tree, status = clang_ast(["clang-18", "-c", str(path), "-o", str(path) + ".o"], folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                trees.append(tree)
            receipt = make_receipt(BEFORE, AFTER, *trees, (3, 3), "return x;")
            self.assertEqual(receipt["target_binding"], "exact_1to1")
            self.assertEqual(len(receipt["edit_groups"]), 1, receipt["edit_groups"])
            self.assertTrue(receipt["edit_groups"][0]["contains_goto"])
            self.assertEqual(classify(receipt)["status"], "undetermined")
            cfg, status = clang_cfg(["clang-18", "-c", str(Path(folder) / "after.c"),
                                     "-o", str(Path(folder) / "after.o")], folder, "parse")
            self.assertEqual(status["exit_code"], 0, status)
            goto = next(block for block in cfg["blocks"].values() if "goto cleanup" in block["body"])
            label = next(block for block in cfg["blocks"].values() if "cleanup:" in block["body"])
            self.assertIn(label["id"], goto["succs"])


if __name__ == "__main__":
    unittest.main()
