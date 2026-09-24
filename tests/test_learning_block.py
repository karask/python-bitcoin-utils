"""Known block vectors and edge cases for the educational block helpers."""

import hashlib
from pathlib import Path
import unittest

from bitcoinutils.block import Block, BlockHeader
from bitcoinutils.learning import (
    create_coinbase_transaction,
    get_block_subsidy,
    trace_merkle_root,
)
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput


def sample_transaction(index: int) -> Transaction:
    return Transaction(
        [TxInput(f"{index:02x}" * 32, 0)],
        [TxOutput(index, Script(["OP_1"]))],
    )


class TestLearningBlock(unittest.TestCase):
    def test_subsidy_boundaries_and_networks(self):
        self.assertEqual(get_block_subsidy(0), 5_000_000_000)
        self.assertEqual(get_block_subsidy(209_999), 5_000_000_000)
        self.assertEqual(get_block_subsidy(210_000), 2_500_000_000)
        self.assertEqual(get_block_subsidy(840_000), 312_500_000)
        self.assertEqual(get_block_subsidy(150, "regtest"), 2_500_000_000)
        self.assertEqual(get_block_subsidy(150, "testnet4"), 5_000_000_000)
        self.assertEqual(get_block_subsidy(64 * 210_000), 0)
        for invalid in (-1, True, 0x80000000):
            with self.assertRaises(ValueError):
                get_block_subsidy(invalid)
        with self.assertRaises(ValueError):
            get_block_subsidy(0, "unknown")

    def test_coinbase_serialization_and_bip34_height(self):
        payout = TxOutput(312_501_000, Script(["OP_1"]))
        coinbase = create_coinbase_transaction(
            840_000, [payout], fees=1_000, extra_nonce=b"\x01\x02",
            message=b"lab",
        )
        self.assertEqual(coinbase.inputs[0].txid, "00" * 32)
        self.assertEqual(coinbase.inputs[0].txout_index, 0xFFFFFFFF)
        self.assertEqual(coinbase.inputs[0].sequence, b"\xff" * 4)
        self.assertEqual(
            coinbase.inputs[0].script_sig.script[0],
            "0340d10c020102036c6162",
        )
        self.assertEqual(coinbase.outputs[0].amount, 312_501_000)
        self.assertEqual(Transaction.from_raw(coinbase.to_hex()).to_hex(), coinbase.to_hex())

        self.assertEqual(
            create_coinbase_transaction(1, [TxOutput(1, Script(["OP_1"]))])
            .inputs[0].script_sig.script[0], "5100",
        )
        self.assertEqual(
            create_coinbase_transaction(128, [TxOutput(1, Script(["OP_1"]))])
            .inputs[0].script_sig.script[0], "028000",
        )

    def test_coinbase_rejects_invalid_reward_and_script(self):
        script = Script(["OP_1"])
        with self.assertRaisesRegex(ValueError, "exceed"):
            create_coinbase_transaction(
                840_000, [TxOutput(312_500_001, script)]
            )
        with self.assertRaisesRegex(ValueError, "fees"):
            create_coinbase_transaction(840_000, [TxOutput(1, script)], fees=-1)
        with self.assertRaisesRegex(ValueError, "100 bytes"):
            create_coinbase_transaction(
                840_000, [TxOutput(1, script)], message=b"x" * 100
            )
        with self.assertRaises(TypeError):
            create_coinbase_transaction(840_000, [TxOutput(1, script)], extra_nonce="01")
        with self.assertRaises(ValueError):
            create_coinbase_transaction(840_000, [])
        with self.assertRaisesRegex(ValueError, "money range"):
            create_coinbase_transaction(
                840_000,
                [TxOutput(2_100_000_000_000_000, script), TxOutput(1, script)],
                fees=2_100_000_000_000_000,
            )

    def test_merkle_byte_order_odd_leaf_and_mutation(self):
        txs = [sample_transaction(index) for index in (1, 2, 3)]
        trace = trace_merkle_root(txs)
        self.assertEqual(trace["txids"], [tx.get_txid() for tx in txs])
        self.assertEqual(trace["levels"][0], trace["txids"])
        self.assertEqual(trace["root"], trace["levels"][-1][0])
        self.assertEqual(trace["root_internal"], bytes.fromhex(trace["root"])[::-1].hex())
        self.assertEqual([pair["duplicated"] for pair in trace["pairs"]], [False, True, False])
        self.assertFalse(trace["mutated"])

        pair = trace["pairs"][0]
        expected_preimage = bytes.fromhex(txs[0].get_txid())[::-1] + bytes.fromhex(txs[1].get_txid())[::-1]
        expected_parent = hashlib.sha256(hashlib.sha256(expected_preimage).digest()).digest()
        self.assertEqual(pair["preimage"], expected_preimage.hex())
        self.assertEqual(pair["parent_internal"], expected_parent.hex())
        self.assertNotEqual(
            trace["root"],
            trace_merkle_root([txs[1], txs[0], txs[2]])["root"],
        )
        self.assertTrue(trace_merkle_root([txs[0], txs[0]])["mutated"])
        self.assertEqual(trace_merkle_root([txs[0]])["root"], txs[0].get_txid())
        with self.assertRaises(ValueError):
            trace_merkle_root([])
        with self.assertRaises(TypeError):
            trace_merkle_root([txs[0], "not a transaction"])

        header = BlockHeader(
            version=2, previous_block_hash=bytes(32),
            merkle_root=bytes.fromhex(trace["root"]), timestamp=1_700_000_000,
            target_bits=0x200FFFFF, nonce=0,
        )
        self.assertEqual(header.serialize_header()[36:68].hex(), trace["root_internal"])

    def test_merkle_root_matches_historical_block(self):
        block_hex = (Path(__file__).with_name("legacy_block.txt")).read_text()
        block = Block.from_raw(block_hex)
        trace = trace_merkle_root(block.transactions)
        self.assertEqual(len(trace["txids"]), 162)
        self.assertEqual(trace["root"], block.header.merkle_root.hex())
        self.assertFalse(trace["mutated"])


if __name__ == "__main__":
    unittest.main()
