import unittest

from memory_analyzer import MemoryAnalyzer


class TestMemoryAnalyzer(unittest.TestCase):
    def test_detects_large_integer(self):
        analyzer = MemoryAnalyzer()
        self.assertTrue(analyzer.check_overflow(2**64))
        self.assertFalse(analyzer.check_overflow(100))

    def test_signed_64_bit_boundaries(self):
        analyzer = MemoryAnalyzer()
        cases = (
            (-9223372036854775809, True),
            (-9223372036854775808, False),
            (9223372036854775807, False),
            (9223372036854775808, True),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertIs(analyzer.check_overflow(value), expected)
