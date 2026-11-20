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
    def _receipt(self, before, after, before_line, expression, contract_calls=()):
        with tempfile.TemporaryDirectory() as folder:
            trees = []
            for side, source in (("before", before), ("after", after)):
                path = Path(folder) / (side + ".c")
                path.write_text(source, encoding="utf-8")
                tree, status = clang_ast(["clang-18", "-c", str(path), "-o", str(path) + ".o"],
                                         folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                trees.append(tree)
            return make_receipt(before, after, *trees, before_line, expression, contract_calls)

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_guard_with_stateful_side_effect_is_confounded(self):
        before = ("void tick(void);\nint parse(int n, int *data, int *fallback) {\n"
                  "  if (n > 0) { }\n  return data[0];\n}\n")
        for body in ("data = fallback;", "data -= 4;", "tick();", "int state = n;"):
            with self.subTest(body=body):
                after = before.replace("if (n > 0) { }", f"if (n > 0) {{ {body} }}")
                receipt = self._receipt(before, after, 4, "data[0]")
                self.assertIn("unrelated", receipt["edit_groups"][0]["roles"], receipt)
                self.assertEqual(classify(receipt)["status"], "confounded")

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_target_line_moves_and_target_edit_is_confounded(self):
        before = "int parse(int n, int *data) {\n  if (n > 0) { }\n  return data[0];\n}\n"
        inserted = before.replace("  return data[0];", "  if (n > 1) { }\n  return data[0];")
        moved = self._receipt(before, inserted, 3, "data[0]")
        self.assertEqual(moved["target_lines"], [3, 4])
        self.assertEqual(moved["target_binding"], "exact_1to1")
        changed = self._receipt(before, before.replace("data[0]", "data[1]"), 3, "data[0]")
        self.assertIn("target", changed["edit_groups"][0]["roles"])
        self.assertEqual(classify(changed)["status"], "confounded")

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_utf8_comment_before_target_uses_byte_offsets(self):
        before = "/* 中文载荷 */\nint parse(int n, int *data) {\n  return data[0];\n}\n"
        after = before.replace("  return data[0];", "  if (n > 0) { }\n  return data[0];")
        receipt = self._receipt(before, after, 3, "data[0]")
        self.assertEqual(receipt["target_lines"], [3, 4])
        self.assertEqual(receipt["target_binding"], "exact_1to1")

    def test_target_line_without_matching_ast_expression_is_unproven(self):
        source = "int parse(int x) {\n  return x;\n}\n"
        fake = {"kind": "FunctionDecl", "inner": [
            {"kind": "CompoundStmt", "range": {"begin": {"line": 2}}}]}
        receipt = make_receipt(source, source, fake, fake,
                               (2, 2), "return x;")
        self.assertEqual(receipt["target_binding"], "unproven")

    @unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
    def test_whitespace_hunk_does_not_create_second_semantic_region(self):
        before = ("int parse(int n, int *data) {\n"
                  "  int pad = 0;\n  pad += 1;\n  pad += 2;\n"
                  "  if (n > 0) { }\n  return data[0];\n}\n")
        after = before.replace("  int pad = 0;", "    int pad = 0;").replace(
            "if (n > 0)", "if (n > 1)")
        receipt = self._receipt(before, after, 6, "data[0]")
        self.assertEqual(len(receipt["edit_groups"]), 1, receipt)
        self.assertEqual(classify(receipt)["status"], "admitted", receipt)

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
