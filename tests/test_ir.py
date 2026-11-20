import unittest
from varyroot.ir import expression_type
from varyroot.checks import Diagnostic


class Grammar(unittest.TestCase):
    def test_type_failures(self):
        for expr in [{"var": "undeclared"}, {"type": "bytes"}, {"type": "bytes", "value": False},
                     {"op": "lt", "args": [{"var": "n"}, {"type": "bytes", "value": 3}]}]:
            with self.subTest(expr=expr), self.assertRaises(Diagnostic) as cm:
                expression_type(expr, {"n": "elements"}, "guard")
            self.assertEqual(cm.exception.detail["code"], "invalid_ir")

    def test_false_and_zero_are_values(self):
        self.assertEqual(expression_type(False, {}, "flag"), "bool")
        self.assertEqual(expression_type({"type": "bytes", "value": 0}, {}, "offset"), "bytes")
