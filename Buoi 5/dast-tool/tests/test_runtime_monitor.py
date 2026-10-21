import os
import unittest

from runtime_monitor import RuntimeMonitor


class TestRuntimeMonitor(unittest.TestCase):
    def test_reads_current_process_memory(self):
        monitor = RuntimeMonitor(os.getpid())
        self.assertGreater(monitor.get_memory_usage(), 0)
