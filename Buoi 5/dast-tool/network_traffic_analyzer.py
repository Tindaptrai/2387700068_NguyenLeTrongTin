import psutil


class NetworkTrafficAnalyzer:
    def get_network_stats(self):
        counters = psutil.net_io_counters(pernic=True) or {}
        return {
            interface: stats._asdict()
            for interface, stats in counters.items()
        }
