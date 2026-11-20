"""Docker role runtime preserves a writable private temporary directory."""
from unittest import TestCase

from varyroot import sandbox


class SandboxVmTests(TestCase):
    def test_docker_role_has_private_tmpfs(self):
        self.assertTrue(hasattr(sandbox, 'docker_run_options'))
        options = sandbox.docker_run_options()
        pairs = list(zip(options, options[1:]))
        self.assertIn(('--tmpfs', '/tmp:rw,exec,nosuid,nodev,mode=1777'), pairs)
