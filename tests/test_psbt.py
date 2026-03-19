# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import unittest

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.constants import SIGHASH_ALL
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, TxWitnessInput
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis, h_to_b, b_to_h
from bitcoinutils.psbt import PSBT, PSBTInput, _is_p2pkh, _is_p2wpkh, _is_p2sh, _is_p2wsh


class TestPSBTCreator(unittest.TestCase):
    """Test PSBT creation from an unsigned transaction."""

    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
        )
        self.txout = TxOutput(
            to_satoshis(0.1),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    "fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a",
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        self.tx = Transaction([self.txin], [self.txout])

    def test_create_psbt(self):
        psbt = PSBT(self.tx)
        self.assertEqual(len(psbt.inputs), 1)
        self.assertEqual(len(psbt.outputs), 1)
        # Unsigned tx should have empty scriptSigs
        self.assertEqual(psbt.tx.inputs[0].script_sig.script, [])
        self.assertFalse(psbt.tx.has_segwit)

    def test_create_from_transaction_method(self):
        psbt = self.tx.to_psbt()
        self.assertIsInstance(psbt, PSBT)
        self.assertEqual(len(psbt.inputs), 1)


class TestPSBTSerialization(unittest.TestCase):
    """Test round-trip serialization."""

    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
        )
        self.txout = TxOutput(
            to_satoshis(0.1),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    "fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a",
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        self.tx = Transaction([self.txin], [self.txout])

    def test_round_trip_bytes(self):
        psbt = PSBT(self.tx)
        raw = psbt.to_bytes()
        psbt2 = PSBT.from_bytes(raw)
        self.assertEqual(psbt2.to_bytes(), raw)

    def test_round_trip_base64(self):
        psbt = PSBT(self.tx)
        b64 = psbt.to_base64()
        psbt2 = PSBT.from_base64(b64)
        self.assertEqual(psbt2.to_base64(), b64)

    def test_round_trip_hex(self):
        psbt = PSBT(self.tx)
        hex_str = psbt.to_hex()
        psbt2 = PSBT.from_hex(hex_str)
        self.assertEqual(psbt2.to_hex(), hex_str)

    def test_magic_bytes(self):
        psbt = PSBT(self.tx)
        raw = psbt.to_bytes()
        self.assertTrue(raw.startswith(b"psbt\xff"))

    def test_invalid_magic(self):
        with self.assertRaises(ValueError):
            PSBT.from_bytes(b"invalid_data")


class TestPSBTSignP2PKH(unittest.TestCase):
    """Full lifecycle: create -> update -> sign -> finalize -> extract for P2PKH."""

    def setUp(self):
        setup("testnet")
        self.sk = PrivateKey("cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9")
        self.from_addr = self.sk.get_public_key().get_address()

        self.txin = TxInput(
            "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c",
            0,
            sequence=b"\xff\xff\xff\xff",
        )
        self.txout = TxOutput(
            to_satoshis(0.1),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    "fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a",
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )
        self.change_txout = TxOutput(
            to_satoshis(0.29),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    "c992931350c9ba48538003706953831402ea34ea",
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )

        # Build the previous transaction for non-witness UTXO
        prev_txout = TxOutput(
            to_satoshis(0.4),
            self.from_addr.to_script_pub_key(),
        )
        self.prev_tx = Transaction(
            [TxInput("01" * 32, 0)],
            [prev_txout],
        )

    def test_p2pkh_full_lifecycle(self):
        tx = Transaction([self.txin], [self.txout, self.change_txout])
        psbt = PSBT(tx)

        # Update with non-witness UTXO
        psbt.update_input(0, non_witness_utxo=self.prev_tx)

        # Sign
        signed = psbt.sign_input(0, self.sk)
        self.assertTrue(signed)
        self.assertEqual(len(psbt.inputs[0].partial_sigs), 1)

        # Finalize
        psbt.finalize_input(0)
        self.assertIsNotNone(psbt.inputs[0].final_scriptsig)

        # Extract
        final_tx = psbt.extract_transaction()
        self.assertIsInstance(final_tx, Transaction)
        # Should have a non-empty scriptSig
        self.assertTrue(len(final_tx.inputs[0].script_sig.script) > 0)

    def test_p2pkh_matches_direct_signing(self):
        """Verify PSBT-signed tx matches directly-signed tx."""
        tx = Transaction(
            [self.txin], [self.txout, self.change_txout]
        )

        # Direct signing
        from_script = self.from_addr.to_script_pub_key()
        sig = self.sk.sign_input(tx, 0, from_script)
        pk_hex = self.sk.get_public_key().to_hex()
        tx.inputs[0].script_sig = Script([sig, pk_hex])
        direct_hex = tx.serialize()

        # PSBT signing
        tx2 = Transaction(
            [
                TxInput(
                    "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c",
                    0,
                    sequence=b"\xff\xff\xff\xff",
                )
            ],
            [self.txout, self.change_txout],
        )
        psbt = PSBT(tx2)
        psbt.update_input(0, non_witness_utxo=self.prev_tx)
        psbt.sign_input(0, self.sk)
        psbt.finalize_input(0)
        final_tx = psbt.extract_transaction()
        psbt_hex = final_tx.serialize()

        self.assertEqual(psbt_hex, direct_hex)


class TestPSBTSignP2WPKH(unittest.TestCase):
    """Full lifecycle for native segwit P2WPKH."""

    def setUp(self):
        setup("testnet")
        self.sk = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.pubkey = self.sk.get_public_key()
        self.p2wpkh_addr = self.pubkey.get_segwit_address()
        self.p2pkh_addr = self.pubkey.get_address()

        self.txin = TxInput(
            "b3ca1c4cc778380d1e5376a5517445104e46e97176e40741508a3b07a6483ad3",
            0,
            sequence=b"\xff\xff\xff\xff",
        )
        self.txin_amount = to_satoshis(0.0099)
        self.txout = TxOutput(
            to_satoshis(0.0098), self.p2pkh_addr.to_script_pub_key()
        )

    def test_p2wpkh_full_lifecycle(self):
        tx = Transaction([self.txin], [self.txout], has_segwit=True)
        psbt = PSBT(tx)

        witness_utxo = TxOutput(
            self.txin_amount, self.p2wpkh_addr.to_script_pub_key()
        )
        psbt.update_input(0, witness_utxo=witness_utxo)

        signed = psbt.sign_input(0, self.sk)
        self.assertTrue(signed)

        psbt.finalize_input(0)
        self.assertIsNotNone(psbt.inputs[0].final_scriptwitness)
        self.assertEqual(len(psbt.inputs[0].final_scriptwitness), 2)

        final_tx = psbt.extract_transaction()
        self.assertTrue(final_tx.has_segwit)
        self.assertEqual(len(final_tx.witnesses), 1)

    def test_p2wpkh_matches_direct_signing(self):
        tx = Transaction([self.txin], [self.txout], has_segwit=True)
        p2pkh_redeem = Script(
            [
                "OP_DUP",
                "OP_HASH160",
                self.p2pkh_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        )
        sig = self.sk.sign_segwit_input(tx, 0, p2pkh_redeem, self.txin_amount)
        pk_hex = self.pubkey.to_hex()
        tx.witnesses = [TxWitnessInput([sig, pk_hex])]
        direct_hex = tx.serialize()

        tx2 = Transaction(
            [
                TxInput(
                    "b3ca1c4cc778380d1e5376a5517445104e46e97176e40741508a3b07a6483ad3",
                    0,
                    sequence=b"\xff\xff\xff\xff",
                )
            ],
            [self.txout],
            has_segwit=True,
        )
        psbt = PSBT(tx2)
        witness_utxo = TxOutput(
            self.txin_amount, self.p2wpkh_addr.to_script_pub_key()
        )
        psbt.update_input(0, witness_utxo=witness_utxo)
        psbt.sign_input(0, self.sk)
        psbt.finalize_input(0)
        final_tx = psbt.extract_transaction()
        psbt_hex = final_tx.serialize()

        self.assertEqual(psbt_hex, direct_hex)


class TestPSBTSignP2SHP2WPKH(unittest.TestCase):
    """Full lifecycle for P2SH-wrapped segwit P2WPKH."""

    def setUp(self):
        setup("testnet")
        self.sk = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.pubkey = self.sk.get_public_key()
        self.p2wpkh_addr = self.pubkey.get_segwit_address()
        self.p2pkh_addr = self.pubkey.get_address()

        # The redeem script is the P2WPKH scriptPubKey
        self.redeem_script = self.p2wpkh_addr.to_script_pub_key()

        # The P2SH address wraps the P2WPKH
        self.p2sh_script = self.redeem_script.to_p2sh_script_pub_key()

        self.txin = TxInput(
            "a3ca1c4cc778380d1e5376a5517445104e46e97176e40741508a3b07a6483ad3",
            0,
            sequence=b"\xff\xff\xff\xff",
        )
        self.txin_amount = to_satoshis(0.01)
        self.txout = TxOutput(
            to_satoshis(0.0099), self.p2pkh_addr.to_script_pub_key()
        )

    def test_p2sh_p2wpkh_lifecycle(self):
        tx = Transaction([self.txin], [self.txout], has_segwit=True)
        psbt = PSBT(tx)

        witness_utxo = TxOutput(self.txin_amount, self.p2sh_script)
        psbt.update_input(
            0,
            witness_utxo=witness_utxo,
            redeem_script=self.redeem_script,
        )

        signed = psbt.sign_input(0, self.sk)
        self.assertTrue(signed)

        psbt.finalize_input(0)
        psi = psbt.inputs[0]
        self.assertIsNotNone(psi.final_scriptsig)
        self.assertIsNotNone(psi.final_scriptwitness)

        final_tx = psbt.extract_transaction()
        self.assertTrue(final_tx.has_segwit)
        # scriptSig should push the redeem script
        self.assertTrue(len(final_tx.inputs[0].script_sig.script) > 0)


class TestPSBTSignP2WSH(unittest.TestCase):
    """2-of-2 multisig P2WSH: two signers, combine, finalize."""

    def setUp(self):
        setup("testnet")
        self.sk1 = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.sk2 = PrivateKey.from_wif(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )
        self.pk1 = self.sk1.get_public_key()
        self.pk2 = self.sk2.get_public_key()
        pk1_hex = self.pk1.to_hex()
        pk2_hex = self.pk2.to_hex()

        # 2-of-2 multisig witness script
        self.witness_script = Script(["OP_2", pk1_hex, pk2_hex, "OP_2", "OP_CHECKMULTISIG"])
        self.p2wsh_script = self.witness_script.to_p2wsh_script_pub_key()

        self.txin = TxInput(
            "c3ca1c4cc778380d1e5376a5517445104e46e97176e40741508a3b07a6483ad3",
            0,
            sequence=b"\xff\xff\xff\xff",
        )
        self.txin_amount = to_satoshis(0.01)
        self.txout = TxOutput(
            to_satoshis(0.0099),
            Script(
                [
                    "OP_DUP",
                    "OP_HASH160",
                    "fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a",
                    "OP_EQUALVERIFY",
                    "OP_CHECKSIG",
                ]
            ),
        )

    def test_p2wsh_two_signers(self):
        tx = Transaction([self.txin], [self.txout], has_segwit=True)

        # Signer 1
        psbt1 = PSBT(tx)
        witness_utxo = TxOutput(self.txin_amount, self.p2wsh_script)
        psbt1.update_input(0, witness_utxo=witness_utxo, witness_script=self.witness_script)
        psbt1.sign_input(0, self.sk1)

        # Signer 2
        psbt2 = PSBT(tx)
        psbt2.update_input(0, witness_utxo=witness_utxo, witness_script=self.witness_script)
        psbt2.sign_input(0, self.sk2)

        # Combine
        combined = psbt1.combine(psbt2)
        self.assertEqual(len(combined.inputs[0].partial_sigs), 2)

        # Finalize
        combined.finalize_input(0)
        psi = combined.inputs[0]
        self.assertIsNotNone(psi.final_scriptwitness)
        # witness: OP_0 (empty), sig1, sig2, witness_script
        self.assertEqual(len(psi.final_scriptwitness), 4)

        # Extract
        final_tx = combined.extract_transaction()
        self.assertTrue(final_tx.has_segwit)


class TestPSBTCombiner(unittest.TestCase):
    """Test combining PSBTs from different signers."""

    def setUp(self):
        setup("testnet")
        self.sk1 = PrivateKey.from_wif(
            "cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo"
        )
        self.sk2 = PrivateKey.from_wif(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )

    def test_combine_mismatched_tx(self):
        tx1 = Transaction(
            [TxInput("a" * 64, 0)],
            [TxOutput(1000, Script(["OP_DUP", "OP_HASH160", "ab" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]))],
        )
        tx2 = Transaction(
            [TxInput("b" * 64, 0)],
            [TxOutput(1000, Script(["OP_DUP", "OP_HASH160", "ab" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]))],
        )
        psbt1 = PSBT(tx1)
        psbt2 = PSBT(tx2)
        with self.assertRaises(ValueError):
            psbt1.combine(psbt2)

    def test_combine_round_trip(self):
        """Combine, serialize, deserialize, compare."""
        pk1_hex = self.sk1.get_public_key().to_hex()
        pk2_hex = self.sk2.get_public_key().to_hex()
        ws = Script(["OP_2", pk1_hex, pk2_hex, "OP_2", "OP_CHECKMULTISIG"])
        p2wsh = ws.to_p2wsh_script_pub_key()

        tx = Transaction(
            [TxInput("d3ca1c4cc778380d1e5376a5517445104e46e97176e40741508a3b07a6483ad3", 0)],
            [TxOutput(to_satoshis(0.009), Script(["OP_DUP", "OP_HASH160", "ab" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]))],
            has_segwit=True,
        )
        witness_utxo = TxOutput(to_satoshis(0.01), p2wsh)

        psbt1 = PSBT(tx)
        psbt1.update_input(0, witness_utxo=witness_utxo, witness_script=ws)
        psbt1.sign_input(0, self.sk1)

        psbt2 = PSBT(tx)
        psbt2.update_input(0, witness_utxo=witness_utxo, witness_script=ws)
        psbt2.sign_input(0, self.sk2)

        combined = psbt1.combine(psbt2)
        b64 = combined.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertEqual(len(restored.inputs[0].partial_sigs), 2)
        self.assertEqual(restored.to_base64(), b64)


class TestPSBTEdgeCases(unittest.TestCase):
    """Edge cases and error handling."""

    def setUp(self):
        setup("testnet")

    def test_extract_before_finalization(self):
        tx = Transaction(
            [TxInput("ab" * 32, 0)],
            [TxOutput(1000, Script(["OP_DUP", "OP_HASH160", "cd" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]))],
        )
        psbt = PSBT(tx)
        with self.assertRaises(ValueError):
            psbt.extract_transaction()

    def test_sign_without_utxo(self):
        sk = PrivateKey.from_wif("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
        tx = Transaction(
            [TxInput("ab" * 32, 0)],
            [TxOutput(1000, Script(["OP_DUP", "OP_HASH160", "cd" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]))],
        )
        psbt = PSBT(tx)
        with self.assertRaises(ValueError):
            psbt.sign_input(0, sk)

    def test_already_finalized(self):
        """Finalize should be a no-op on already finalized input."""
        tx = Transaction(
            [TxInput("ab" * 32, 0)],
            [TxOutput(1000, Script(["OP_DUP", "OP_HASH160", "cd" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"]))],
        )
        psbt = PSBT(tx)
        # Manually set final_scriptsig
        psbt.inputs[0].final_scriptsig = Script(["aa" * 32])
        # Should not raise
        psbt.finalize_input(0)


class TestScriptDetection(unittest.TestCase):
    """Test script type detection helpers."""

    def test_p2pkh(self):
        s = Script(["OP_DUP", "OP_HASH160", "ab" * 20, "OP_EQUALVERIFY", "OP_CHECKSIG"])
        self.assertTrue(_is_p2pkh(s))
        self.assertFalse(_is_p2sh(s))
        self.assertFalse(_is_p2wpkh(s))

    def test_p2sh(self):
        s = Script(["OP_HASH160", "ab" * 20, "OP_EQUAL"])
        self.assertTrue(_is_p2sh(s))
        self.assertFalse(_is_p2pkh(s))

    def test_p2wpkh(self):
        s = Script(["OP_0", "ab" * 20])
        self.assertTrue(_is_p2wpkh(s))
        self.assertFalse(_is_p2wsh(s))

    def test_p2wsh(self):
        s = Script(["OP_0", "ab" * 32])
        self.assertTrue(_is_p2wsh(s))
        self.assertFalse(_is_p2wpkh(s))


if __name__ == "__main__":
    unittest.main()
