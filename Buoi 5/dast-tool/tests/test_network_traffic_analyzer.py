import unittest

from network_traffic_analyzer import NetworkTrafficAnalyzer


class TestNetworkTrafficAnalyzer(unittest.TestCase):
    def test_returns_interface_mapping(self):
        stats = NetworkTrafficAnalyzer().get_network_stats()
        self.assertIsInstance(stats, dict)
