import gc


class MemoryAnalyzer:
    def check_memory_leaks(self):
        collected = gc.collect()
        return {
            "collected_objects": collected,
            "uncollectable_objects": len(gc.garbage),
        }

    def check_overflow(self, value):
        return type(value) is int and (
            value < -(2**63) or value > 2**63 - 1
        )
