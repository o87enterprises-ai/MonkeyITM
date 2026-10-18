import sys, unittest
sys.path.insert(0, '/workspace')
from app import config


class T(unittest.TestCase):
    def test_port(self):
        self.assertEqual(config.DEFAULT_PORT, 8080)


if __name__ == '__main__':
    unittest.main()
