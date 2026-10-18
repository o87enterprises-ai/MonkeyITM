import unittest

import calc


class TestCalc(unittest.TestCase):
    def test_add(self):
        self.assertEqual(calc.add(2, 3), 5)
        self.assertEqual(calc.add(-1, 1), 0)

    def test_mean(self):
        self.assertEqual(calc.mean([1, 2, 3]), 2)

    def test_mean_empty(self):
        self.assertEqual(calc.mean([]), 0.0)


if __name__ == "__main__":
    unittest.main()
