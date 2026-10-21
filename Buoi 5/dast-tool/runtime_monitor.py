import psutil


class RuntimeMonitor:
    def __init__(self, pid):
        self.pid = int(pid)
        self.process = psutil.Process(self.pid)

    def get_cpu_usage(self):
        return self.process.cpu_percent(interval=0.1)

    def get_memory_usage(self):
        return self.process.memory_info().rss

    def get_open_files(self):
        try:
            return [file.path for file in self.process.open_files()]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []
