import os

from memory_analyzer import MemoryAnalyzer
from network_traffic_analyzer import NetworkTrafficAnalyzer
from runtime_monitor import RuntimeMonitor
from security_behavior_checker import SecurityBehaviorChecker
from virtual_sandbox import VirtualSandbox


def main():
    pid = os.getpid()
    print("[+] Monitoring current process:", pid)
    monitor = RuntimeMonitor(pid)
    print("CPU Usage:", monitor.get_cpu_usage())
    print("Memory Usage:", monitor.get_memory_usage())
    print("Open Files:", monitor.get_open_files())

    memory = MemoryAnalyzer()
    print("Memory Check:", memory.check_memory_leaks())
    print("Overflow Test:", memory.check_overflow(2**64))
    print("Network Stats:", NetworkTrafficAnalyzer().get_network_stats())
    print("Suspicious Calls:", SecurityBehaviorChecker().suspicious_calls(__file__))

    stdout, stderr = VirtualSandbox().run_isolated("echo Hello Sandbox")
    print("Sandbox stdout:", stdout, end="")
    print("Sandbox stderr:", stderr)


if __name__ == "__main__":
    main()
