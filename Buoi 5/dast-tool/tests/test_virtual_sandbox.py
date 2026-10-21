import unittest

from virtual_sandbox import VirtualSandbox


class TestVirtualSandbox(unittest.TestCase):
    def test_echo_demo_returns_output(self):
        stdout, stderr = VirtualSandbox().run_isolated("echo test")
        self.assertIn("test", stdout)
        self.assertEqual(stderr, "")

    def test_rejects_other_commands(self):
        with self.assertRaises(PermissionError):
            VirtualSandbox().run_isolated("python -c print(1)")
