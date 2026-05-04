import unittest

from bitcoinutils.setup import (
    setup,
    is_mainnet,
    is_testnet,
    is_testnet4,
    is_signet,
    is_regtest,
)


class TestSetup(unittest.TestCase):
    def test_network_predicates(self):
        setup("mainnet")
        self.assertTrue(is_mainnet())
        self.assertFalse(is_testnet())

        setup("testnet")
        self.assertTrue(is_testnet())

        setup("testnet4")
        self.assertTrue(is_testnet4())

        setup("signet")
        self.assertTrue(is_signet())

        setup("regtest")
        self.assertTrue(is_regtest())

    def test_invalid_network(self):
        with self.assertRaises(ValueError):
            setup("badnet")

        setup("testnet")


if __name__ == "__main__":
    unittest.main()
