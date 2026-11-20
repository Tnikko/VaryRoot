"""Build-capture admission for the real Ettercap source target."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import shutil

from tools.oob_feasibility.build import capture_compile_commands, run_target_compile, validate_capture


class BuildCaptureTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang-18"), "locked compiler unavailable")
    def test_replays_captured_compile_command_for_original_unit(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src/dissectors/ec_vnc.c"
            source.parent.mkdir(parents=True)
            source.write_text("int vnc(void) { return 7; }\n")
            output = root / "vnc.o"
            commands = root / "compile_commands.json"
            commands.write_text(json.dumps([{
                "directory": str(root), "file": str(source),
                "arguments": ["clang-18", "-c", str(source), "-o", str(output)],
            }]))
            capture = run_target_compile(commands, source)
            self.assertEqual(capture["exit_code"], 0, capture["stderr"])
            self.assertTrue(output.is_file())
            self.assertEqual(validate_capture(capture, hashlib.sha256(source.read_bytes()).hexdigest()), capture)

    def test_captures_exact_source_among_other_translation_units(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src/dissectors/ec_vnc.c"
            source.parent.mkdir(parents=True)
            source.write_text("int vnc(void) { return 0; }\n")
            other = root / "src/dissectors/ec_ftp.c"
            other.write_text("int ftp(void) { return 0; }\n")
            commands = root / "compile_commands.json"
            commands.write_text(json.dumps([
                {"directory": str(root), "file": str(other),
                 "arguments": ["clang-18", "-c", str(other), "-o", "ftp.o"]},
                {"directory": str(root), "file": str(source),
                 "arguments": ["clang-18", "-c", str(source), "-o", "vnc.o"]},
            ]))
            capture = capture_compile_commands(commands, source, exit_code=0)
            self.assertEqual(capture["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertIn(str(source), capture["argv"])
            self.assertNotIn(str(other), capture["argv"])

    def test_requires_original_translation_unit_and_digest(self):
        expected = "a" * 64
        good = {
            "source_path": "/checkout/src/dissectors/ec_vnc.c",
            "source_sha256": expected,
            "argv": ["clang-18", "-c", "/checkout/src/dissectors/ec_vnc.c", "-o", "ec_vnc.o"],
            "exit_code": 0,
        }
        self.assertEqual(validate_capture(good, expected)["source_sha256"], expected)

        wrong_unit = dict(good, source_path="/checkout/tests/vnc_skeleton.c")
        with self.assertRaisesRegex(ValueError, "target_translation_unit"):
            validate_capture(wrong_unit, expected)

        wrong_digest = dict(good, source_sha256="b" * 64)
        with self.assertRaisesRegex(ValueError, "source_digest"):
            validate_capture(wrong_digest, expected)

        not_compiled = dict(good, exit_code=1)
        with self.assertRaisesRegex(ValueError, "compile_failed"):
            validate_capture(not_compiled, expected)


if __name__ == "__main__":
    unittest.main()
