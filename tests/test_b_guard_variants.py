"""Concrete Clang regressions for equivalent interval guards and early exits."""

import shutil
import tempfile
import unittest
from pathlib import Path

from varyroot.b_clang_receipt import clang_ast, clang_cfg
from varyroot.b_interval_ir import extract_interval_facts, make_interval_pair, predict_interval


@unittest.skipUnless(shutil.which("clang-18"), "Clang 18 unavailable")
class IntervalGuardVariantsTest(unittest.TestCase):
    def test_comparisons_thresholds_and_sibling_early_returns(self):
        config = {"target_expression": "memcpy(dst, cursor, 8)", "target_call": "memcpy",
                  "total_expr": "len", "remaining_expr": "end - cursor",
                  "pointer_expr": "cursor", "width": 8}
        pair = make_interval_pair("equivalent_guard_test", "logical_span")
        cases = (
            ("8 <= end - cursor", "wrapped", (False, True), 10, ("quiet", "quiet")),
            ("end - cursor > 7", "wrapped", (False, True), 10, ("quiet", "quiet")),
            ("7 < end - cursor", "wrapped", (False, True), 10, ("quiet", "quiet")),
            ("cursor + 8 <= end", "wrapped", (False, True), 10, ("quiet", "quiet")),
            ("end >= cursor + 8", "wrapped", (False, True), 10, ("quiet", "quiet")),
            ("len >= 9", "wrapped", (True, False), 9, ("quiet", "report")),
            ("len >= 10", "wrapped", (True, True), 10, ("quiet", "quiet")),
            ("end - cursor >= 9", "wrapped", (False, True), 11, ("quiet", "quiet")),
            ("len < 8", "early", (True, False), 8, ("quiet", "report")),
            ("len <= 7", "early", (True, False), 8, ("quiet", "report")),
            ("end - cursor < 8", "early", (False, True), 10, ("quiet", "quiet")),
            ("cursor + 8 > end", "early", (False, True), 10, ("quiet", "quiet")),
        )
        with tempfile.TemporaryDirectory() as folder:
            for index, (condition, shape, expected_guards, capacity, expected) in enumerate(cases):
                with self.subTest(condition=condition, shape=shape):
                    statement = (f"if ({condition}) return 0;\n  memcpy(dst, cursor, 8);"
                                 if shape == "early" else
                                 f"if ({condition}) {{\n    memcpy(dst, cursor, 8);\n  }}")
                    source = ("#include <string.h>\n"
                              "int parse(char *dst, char *base, int len) {\n"
                              "  char *cursor = base; char *end = base + len;\n"
                              "  cursor += 2;\n  " + statement + "\n  return 0;\n}\n")
                    path = Path(folder) / f"case-{index}.c"
                    path.write_text(source)
                    argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                    ast, status = clang_ast(argv, folder, "parse")
                    self.assertEqual(status["exit_code"], 0, status)
                    cfg, status = clang_cfg(argv, folder, "parse")
                    self.assertEqual(status["exit_code"], 0, status)
                    target_line = next(i for i, line in enumerate(source.splitlines(), 1)
                                       if "memcpy(dst, cursor, 8)" in line)
                    facts = extract_interval_facts(source, ast, cfg, target_line, config)
                    self.assertEqual((facts["total_guard"], facts["remaining_guard"]),
                                     expected_guards, facts)
                    self.assertEqual(facts["capacity"], capacity, facts)
                    self.assertEqual(tuple(predict_interval(pair, facts).values()), expected, facts)

    def test_unsupported_disjunction_and_alias_stay_undetermined(self):
        config = {"target_expression": "memcpy(dst, cursor, 8)", "target_call": "memcpy",
                  "total_expr": "len", "remaining_expr": "end - cursor",
                  "pointer_expr": "cursor", "width": 8}
        with tempfile.TemporaryDirectory() as folder:
            for index, (condition, reason) in enumerate((
                    ("len >= 8 || end - cursor >= 8", "disjunctive_interval_guard_unproven"),
                    ("allows(cursor, end, 8)", "alias_interval_guard_unproven"))):
                source = ("#include <string.h>\nint allows(char *, char *, int);\n"
                          "int parse(char *dst, char *base, int len) {\n"
                          "  char *cursor=base; char *end=base+len; cursor+=2;\n"
                          f"  if ({condition}) {{\n    memcpy(dst, cursor, 8);\n  }}\n"
                          "  return 0;\n}\n")
                path = Path(folder) / f"unsupported-{index}.c"
                path.write_text(source)
                argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
                ast, status = clang_ast(argv, folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                cfg, status = clang_cfg(argv, folder, "parse")
                self.assertEqual(status["exit_code"], 0, status)
                with self.assertRaisesRegex(ValueError, reason):
                    extract_interval_facts(source, ast, cfg, 6, config)

    def test_declared_interval_with_unevaluated_sizeof_bound_is_not_a_definite_no_guard(self):
        config = {"target_expression": "memcpy(dst, cursor, 8)", "target_call": "memcpy",
                  "total_expr": "len", "remaining_expr": "end - cursor",
                  "pointer_expr": "cursor", "width": 8}
        source = ("#include <string.h>\n"
                  "int parse(char *dst, char *base, int len) {\n"
                  "  char *cursor = base; char *end = base + len;\n"
                  "  cursor += 2;\n"
                  "  if (end - cursor >= sizeof(*dst)) {\n"
                  "    memcpy(dst, cursor, 8);\n  }\n  return 0;\n}\n")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sizeof.c"
            path.write_text(source)
            argv = ["clang-18", "-c", str(path), "-o", str(path) + ".o"]
            ast, status = clang_ast(argv, folder, "parse")
            self.assertEqual(status["exit_code"], 0, status)
            cfg, status = clang_cfg(argv, folder, "parse")
            self.assertEqual(status["exit_code"], 0, status)
            with self.assertRaisesRegex(ValueError, "unevaluated_interval_bound"):
                extract_interval_facts(source, ast, cfg, 6, config)


if __name__ == "__main__":
    unittest.main()
