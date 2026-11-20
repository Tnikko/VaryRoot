"""Recovery checks for Step 4a on an explicit Docker role backend."""
import importlib.util
import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'runs/step4-paired/src/prepare4a.py'
spec = importlib.util.spec_from_file_location('prepare4a', MODULE)
prepare4a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare4a)


class Prepare4aVmTests(TestCase):
    def test_reference_build_inputs_are_digest_locked(self):
        self.assertTrue(hasattr(prepare4a, 'locked_dependencies'))
        deps = prepare4a.locked_dependencies()
        self.assertEqual(set(deps), {
            'build.py', 'observer.inc', 'api.inc', 'ld.gold',
            'openldap-include.tar.gz', 'ubuntu24-libc-headers.tar.gz',
        })
        self.assertTrue(all(path.is_file() for path in deps.values()))

    def test_docker_is_an_explicit_supported_backend(self):
        self.assertTrue(hasattr(prepare4a, 'execution_backend'))
        with patch.dict(os.environ, {'VARYROOT_ROLE_BACKEND': 'docker'}):
            self.assertEqual(prepare4a.execution_backend(), 'docker')
        with patch.dict(os.environ, {'VARYROOT_ROLE_BACKEND': ''}):
            with self.assertRaises(ValueError):
                prepare4a.execution_backend()
