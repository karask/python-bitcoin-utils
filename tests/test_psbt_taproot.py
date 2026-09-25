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

"""Tests for Taproot key-path spending in PSBT (BIP-371).

Tests cover:
    - Full P2TR key-path PSBT lifecycle (create → sign → finalize → extract)
    - PSBT-signed transaction matches directly-signed transaction
    - BIP-371 field serialization round-trip
    - Taproot sighash types
    - Multi-input mixed types (P2TR + P2WPKH)
    - Combine preserves Taproot fields
    - Finalization clears Taproot fields
    - Missing tap_key_sig error on finalize
    - Exact witness byte verification
"""

import unittest

from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis, h_to_b, b_to_h
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey, P2pkhAddress
from bitcoinutils.script import Script
from bitcoinutils.constants import (
    TAPROOT_SIGHASH_ALL,
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ANYONECANPAY,
)
from bitcoinutils.psbt import (
    PSBT,
    PSBT_IN_TAP_KEY_SIG,
    PSBT_IN_TAP_INTERNAL_KEY,
    PSBT_IN_TAP_MERKLE_ROOT,
    PSBT_IN_TAP_SCRIPT_SIG,
    PSBT_IN_TAP_LEAF_SCRIPT,
    PSBT_IN_TAP_BIP32_DERIVATION,
    PSBT_OUT_TAP_INTERNAL_KEY,
    PSBT_OUT_TAP_TREE,
    PSBT_OUT_TAP_BIP32_DERIVATION,
)


class TestTaprootPSBTLifecycle(unittest.TestCase):
    """Test the full P2TR key-path PSBT lifecycle."""

    maxDiff = None

    def setUp(self):
        setup("testnet")
        # Keys that correspond to pubkey starting with 02
        self.sk = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
        self.pub = self.sk.get_public_key()
        self.taproot_addr = self.pub.get_taproot_address()
        self.script_pubkey = self.taproot_addr.to_script_pub_key()
        self.x_only_hex = self.pub.to_x_only_hex()

        self.txid = "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56"
        self.vout = 1
        self.amount = to_satoshis(0.00005)

        self.dest = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")
        self.send_amount = to_satoshis(0.00004)

    def _make_psbt(self):
        """Create an unsigned PSBT with witness UTXO attached."""
        txin = TxInput(self.txid, self.vout)
        txout = TxOutput(self.send_amount, self.dest.to_script_pub_key())
        tx = Transaction([txin], [txout], has_segwit=True)
        psbt = PSBT(tx)
        witness_utxo = TxOutput(self.amount, self.script_pubkey)
        psbt.update_input(0, witness_utxo=witness_utxo)
        return psbt

    def test_p2tr_key_path_lifecycle(self):
        """Create → Update → Sign → Finalize → Extract."""
        psbt = self._make_psbt()

        # Sign
        result = psbt.sign_input(0, self.sk)
        self.assertTrue(result)

        # Verify tap_key_sig is set, not partial_sigs
        psi = psbt.inputs[0]
        self.assertIsNotNone(psi.tap_key_sig)
        self.assertIn(len(psi.tap_key_sig), (64, 65))
        self.assertEqual(len(psi.partial_sigs), 0)

        # Verify tap_internal_key auto-populated
        self.assertIsNotNone(psi.tap_internal_key)
        self.assertEqual(len(psi.tap_internal_key), 32)
        self.assertEqual(psi.tap_internal_key, h_to_b(self.x_only_hex))

        # Finalize
        psbt.finalize_input(0)
        self.assertIsNotNone(psi.final_scriptwitness)
        self.assertEqual(len(psi.final_scriptwitness), 1)

        # Extract
        final_tx = psbt.extract_transaction()
        self.assertIsNotNone(final_tx.get_txid())
        self.assertEqual(len(final_tx.witnesses), 1)

    def test_p2tr_matches_direct_signing(self):
        """PSBT-signed tx produces identical output to directly-signed tx."""
        # PSBT path
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk)
        psbt.finalize_input(0)
        psbt_tx = psbt.extract_transaction()

        # Direct signing path
        txin = TxInput(self.txid, self.vout)
        txout = TxOutput(self.send_amount, self.dest.to_script_pub_key())
        direct_tx = Transaction([txin], [txout], has_segwit=True)
        sig_hex = self.sk.sign_taproot_input(
            direct_tx, 0, [self.script_pubkey], [self.amount]
        )
        direct_tx.witnesses.append(TxWitnessInput([sig_hex]))

        # Verify identical txid and raw serialization
        self.assertEqual(psbt_tx.get_txid(), direct_tx.get_txid())
        self.assertEqual(psbt_tx.serialize(), direct_tx.serialize())

    def test_exact_witness_bytes(self):
        """Verify exact witness stack structure for Taproot key-path."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk)

        # Save the signature for later comparison
        tap_key_sig = psbt.inputs[0].tap_key_sig

        psbt.finalize_input(0)
        final_tx = psbt.extract_transaction()

        # Witness should have exactly 1 item: the Schnorr signature
        wit = final_tx.witnesses[0]
        self.assertEqual(len(wit.stack), 1)

        # The witness item should be the tap_key_sig hex
        sig_hex = wit.stack[0]
        self.assertEqual(h_to_b(sig_hex), tap_key_sig)

        # Default sighash (0x00) produces 64-byte signature (no sighash byte appended)
        self.assertEqual(len(tap_key_sig), 64)


class TestTaprootPSBTSighashTypes(unittest.TestCase):
    """Test Taproot signing with different sighash types."""

    def setUp(self):
        setup("testnet")
        self.sk = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
        self.pub = self.sk.get_public_key()
        self.taproot_addr = self.pub.get_taproot_address()
        self.script_pubkey = self.taproot_addr.to_script_pub_key()

        self.txid = "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56"
        self.amount = to_satoshis(0.00005)

    def _make_psbt(self):
        txin = TxInput(self.txid, 1)
        dest = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")
        txout = TxOutput(to_satoshis(0.00004), dest.to_script_pub_key())
        tx = Transaction([txin], [txout], has_segwit=True)
        psbt = PSBT(tx)
        psbt.update_input(0, witness_utxo=TxOutput(self.amount, self.script_pubkey))
        return psbt

    def test_default_sighash_all(self):
        """SIGHASH_ALL (0x01) is mapped to TAPROOT_SIGHASH_ALL (0x00)."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk, sighash=SIGHASH_ALL)
        # Default taproot sighash produces 64-byte sig (no sighash byte appended)
        self.assertEqual(len(psbt.inputs[0].tap_key_sig), 64)

    def test_sighash_none(self):
        """SIGHASH_NONE produces 65-byte sig (sighash byte appended)."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk, sighash=SIGHASH_NONE)
        # Non-default sighash appends the sighash byte
        self.assertEqual(len(psbt.inputs[0].tap_key_sig), 65)

    def test_sighash_single(self):
        """SIGHASH_SINGLE produces 65-byte sig."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk, sighash=SIGHASH_SINGLE)
        self.assertEqual(len(psbt.inputs[0].tap_key_sig), 65)

    def test_sighash_anyonecanpay(self):
        """SIGHASH_ANYONECANPAY|ALL produces 65-byte sig."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk, sighash=SIGHASH_ALL | SIGHASH_ANYONECANPAY)
        self.assertEqual(len(psbt.inputs[0].tap_key_sig), 65)


class TestBIP371FieldRoundTrip(unittest.TestCase):
    """Test BIP-371 field serialization/deserialization round-trip."""

    def setUp(self):
        setup("testnet")

    def _make_base_psbt(self):
        txin = TxInput(
            "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56", 1
        )
        txout = TxOutput(to_satoshis(0.00004), Script(["OP_1", "aa" * 32]))
        tx = Transaction([txin], [txout], has_segwit=True)
        return PSBT(tx)

    def test_tap_key_sig_round_trip(self):
        """tap_key_sig (64 bytes) round-trips correctly."""
        psbt = self._make_base_psbt()
        fake_sig = b"\x01" * 64
        psbt.inputs[0].tap_key_sig = fake_sig

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertEqual(restored.inputs[0].tap_key_sig, fake_sig)

    def test_tap_key_sig_65_bytes_round_trip(self):
        """tap_key_sig (65 bytes, non-default sighash) round-trips correctly."""
        psbt = self._make_base_psbt()
        fake_sig = b"\x02" * 64 + b"\x03"
        psbt.inputs[0].tap_key_sig = fake_sig

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertEqual(restored.inputs[0].tap_key_sig, fake_sig)

    def test_tap_internal_key_round_trip(self):
        """tap_internal_key (32 bytes) round-trips for both inputs and outputs."""
        psbt = self._make_base_psbt()
        fake_key = b"\xab" * 32
        psbt.inputs[0].tap_internal_key = fake_key
        psbt.outputs[0].tap_internal_key = fake_key

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertEqual(restored.inputs[0].tap_internal_key, fake_key)
        self.assertEqual(restored.outputs[0].tap_internal_key, fake_key)

    def test_tap_merkle_root_round_trip(self):
        """tap_merkle_root (32 bytes) round-trips correctly."""
        psbt = self._make_base_psbt()
        fake_root = b"\xcd" * 32
        psbt.inputs[0].tap_merkle_root = fake_root

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertEqual(restored.inputs[0].tap_merkle_root, fake_root)

    def test_tap_script_sig_round_trip(self):
        """tap_script_sig entries round-trip correctly."""
        psbt = self._make_base_psbt()
        xonly = b"\x11" * 32
        leaf_hash = b"\x22" * 32
        sig = b"\x33" * 64
        psbt.inputs[0].tap_script_sigs[(xonly, leaf_hash)] = sig

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertIn((xonly, leaf_hash), restored.inputs[0].tap_script_sigs)
        self.assertEqual(restored.inputs[0].tap_script_sigs[(xonly, leaf_hash)], sig)

    def test_tap_leaf_script_round_trip(self):
        """tap_leaf_script entries round-trip correctly."""
        psbt = self._make_base_psbt()
        control_block = b"\x44" * 33
        script_bytes = b"\x55" * 20
        leaf_ver = 0xC0
        psbt.inputs[0].tap_leaf_scripts[control_block] = (script_bytes, leaf_ver)

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertIn(control_block, restored.inputs[0].tap_leaf_scripts)
        rs_bytes, rs_ver = restored.inputs[0].tap_leaf_scripts[control_block]
        self.assertEqual(rs_bytes, script_bytes)
        self.assertEqual(rs_ver, leaf_ver)

    def test_tap_bip32_derivation_round_trip(self):
        """tap_bip32_derivation entries round-trip correctly for inputs."""
        psbt = self._make_base_psbt()
        xonly = b"\x66" * 32
        leaf_hashes = [b"\x77" * 32, b"\x88" * 32]
        fp = b"\x99" * 4
        path = [0x80000056, 0x80000001, 0x80000000, 0, 0]
        psbt.inputs[0].tap_bip32_derivs[xonly] = (leaf_hashes, fp, path)

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertIn(xonly, restored.inputs[0].tap_bip32_derivs)
        r_hashes, r_fp, r_path = restored.inputs[0].tap_bip32_derivs[xonly]
        self.assertEqual(r_hashes, leaf_hashes)
        self.assertEqual(r_fp, fp)
        self.assertEqual(r_path, path)

    def test_output_tap_tree_round_trip(self):
        """Output tap_tree bytes round-trip correctly."""
        psbt = self._make_base_psbt()
        fake_tree = b"\xaa\xbb\xcc\xdd" * 10
        psbt.outputs[0].tap_tree = fake_tree

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertEqual(restored.outputs[0].tap_tree, fake_tree)

    def test_output_tap_bip32_derivation_round_trip(self):
        """Output tap_bip32_derivation entries round-trip correctly."""
        psbt = self._make_base_psbt()
        xonly = b"\xaa" * 32
        leaf_hashes = [b"\xbb" * 32]
        fp = b"\xcc" * 4
        path = [0x80000056, 0]
        psbt.outputs[0].tap_bip32_derivs[xonly] = (leaf_hashes, fp, path)

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        self.assertIn(xonly, restored.outputs[0].tap_bip32_derivs)
        r_hashes, r_fp, r_path = restored.outputs[0].tap_bip32_derivs[xonly]
        self.assertEqual(r_hashes, leaf_hashes)
        self.assertEqual(r_fp, fp)
        self.assertEqual(r_path, path)

    def test_all_bip371_fields_together(self):
        """All BIP-371 fields set simultaneously round-trip correctly."""
        psbt = self._make_base_psbt()
        psi = psbt.inputs[0]
        pso = psbt.outputs[0]

        # Input fields
        psi.tap_key_sig = b"\x01" * 64
        psi.tap_internal_key = b"\x02" * 32
        psi.tap_merkle_root = b"\x03" * 32
        psi.tap_script_sigs[(b"\x04" * 32, b"\x05" * 32)] = b"\x06" * 64
        psi.tap_leaf_scripts[b"\x07" * 33] = (b"\x08" * 10, 0xC0)
        psi.tap_bip32_derivs[b"\x09" * 32] = ([b"\x0a" * 32], b"\x0b" * 4, [0, 1])

        # Output fields
        pso.tap_internal_key = b"\x0c" * 32
        pso.tap_tree = b"\x0d" * 40
        pso.tap_bip32_derivs[b"\x0e" * 32] = ([], b"\x0f" * 4, [2, 3])

        b64 = psbt.to_base64()
        restored = PSBT.from_base64(b64)
        ri = restored.inputs[0]
        ro = restored.outputs[0]

        self.assertEqual(ri.tap_key_sig, psi.tap_key_sig)
        self.assertEqual(ri.tap_internal_key, psi.tap_internal_key)
        self.assertEqual(ri.tap_merkle_root, psi.tap_merkle_root)
        self.assertEqual(ri.tap_script_sigs, psi.tap_script_sigs)
        self.assertEqual(ri.tap_leaf_scripts, psi.tap_leaf_scripts)
        self.assertEqual(ri.tap_bip32_derivs, psi.tap_bip32_derivs)
        self.assertEqual(ro.tap_internal_key, pso.tap_internal_key)
        self.assertEqual(ro.tap_tree, pso.tap_tree)
        self.assertEqual(ro.tap_bip32_derivs, pso.tap_bip32_derivs)


class TestTaprootCombine(unittest.TestCase):
    """Test that combine() preserves Taproot fields."""

    def setUp(self):
        setup("testnet")

    def _make_psbt(self):
        txin = TxInput(
            "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56", 1
        )
        txout = TxOutput(to_satoshis(0.00004), Script(["OP_1", "aa" * 32]))
        tx = Transaction([txin], [txout], has_segwit=True)
        return PSBT(tx)

    def test_combine_preserves_tap_key_sig(self):
        """Combine merges tap_key_sig from the other PSBT."""
        psbt_a = self._make_psbt()
        psbt_b = self._make_psbt()

        sig = b"\x01" * 64
        psbt_b.inputs[0].tap_key_sig = sig

        combined = psbt_a.combine(psbt_b)
        self.assertEqual(combined.inputs[0].tap_key_sig, sig)

    def test_combine_preserves_tap_internal_key(self):
        """Combine merges tap_internal_key from both PSBTs."""
        psbt_a = self._make_psbt()
        psbt_b = self._make_psbt()

        key = b"\x02" * 32
        psbt_a.inputs[0].tap_internal_key = key
        psbt_b.outputs[0].tap_internal_key = key

        combined = psbt_a.combine(psbt_b)
        self.assertEqual(combined.inputs[0].tap_internal_key, key)
        self.assertEqual(combined.outputs[0].tap_internal_key, key)

    def test_combine_merges_tap_script_sigs(self):
        """Combine merges tap_script_sigs from both PSBTs."""
        psbt_a = self._make_psbt()
        psbt_b = self._make_psbt()

        key_a = (b"\x03" * 32, b"\x04" * 32)
        key_b = (b"\x05" * 32, b"\x06" * 32)
        psbt_a.inputs[0].tap_script_sigs[key_a] = b"\x07" * 64
        psbt_b.inputs[0].tap_script_sigs[key_b] = b"\x08" * 64

        combined = psbt_a.combine(psbt_b)
        self.assertIn(key_a, combined.inputs[0].tap_script_sigs)
        self.assertIn(key_b, combined.inputs[0].tap_script_sigs)


class TestTaprootFinalization(unittest.TestCase):
    """Test finalization behavior for P2TR inputs."""

    def setUp(self):
        setup("testnet")
        self.sk = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
        self.pub = self.sk.get_public_key()
        self.taproot_addr = self.pub.get_taproot_address()
        self.script_pubkey = self.taproot_addr.to_script_pub_key()

    def _make_psbt(self):
        txin = TxInput(
            "7b6412a0eed56338731e83c606f13ebb7a3756b3e4e1dbbe43a7db8d09106e56", 1
        )
        txout = TxOutput(
            to_satoshis(0.00004),
            P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ").to_script_pub_key(),
        )
        tx = Transaction([txin], [txout], has_segwit=True)
        psbt = PSBT(tx)
        psbt.update_input(
            0, witness_utxo=TxOutput(to_satoshis(0.00005), self.script_pubkey)
        )
        return psbt

    def test_finalize_clears_taproot_fields(self):
        """Finalization clears all tap_* fields."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk)

        # Set extra fields to verify they get cleared
        psi = psbt.inputs[0]
        psi.tap_merkle_root = b"\xff" * 32
        psi.tap_bip32_derivs[b"\xaa" * 32] = ([], b"\x00" * 4, [0])

        psbt.finalize_input(0)

        self.assertIsNone(psi.tap_key_sig)
        self.assertIsNone(psi.tap_internal_key)
        self.assertIsNone(psi.tap_merkle_root)
        self.assertEqual(len(psi.tap_script_sigs), 0)
        self.assertEqual(len(psi.tap_leaf_scripts), 0)
        self.assertEqual(len(psi.tap_bip32_derivs), 0)

    def test_finalize_without_tap_key_sig_raises(self):
        """Finalization without tap_key_sig raises ValueError."""
        psbt = self._make_psbt()
        # Don't sign — go straight to finalize
        with self.assertRaises(ValueError) as ctx:
            psbt.finalize_input(0)
        self.assertIn("tap_key_sig", str(ctx.exception))

    def test_finalize_produces_single_witness_item(self):
        """P2TR key-path witness is a single stack item (the signature)."""
        psbt = self._make_psbt()
        psbt.sign_input(0, self.sk)
        psbt.finalize_input(0)

        psi = psbt.inputs[0]
        self.assertEqual(len(psi.final_scriptwitness), 1)


class TestMultiInputMixedTypes(unittest.TestCase):
    """Test PSBT with mixed P2TR and P2WPKH inputs."""

    def setUp(self):
        setup("testnet")
        self.sk1 = PrivateKey("cV3R88re3AZSBnWhBBNdiCKTfwpMKkYYjdiR13HQzsU7zoRNX7JL")
        self.pub1 = self.sk1.get_public_key()
        self.taproot_addr = self.pub1.get_taproot_address()
        self.taproot_spk = self.taproot_addr.to_script_pub_key()

        self.sk2 = PrivateKey("cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs")
        self.pub2 = self.sk2.get_public_key()
        self.segwit_addr = self.pub2.get_segwit_address()
        self.segwit_spk = self.segwit_addr.to_script_pub_key()

    def test_mixed_p2tr_p2wpkh(self):
        """PSBT with one P2TR and one P2WPKH input."""
        txin1 = TxInput("aaaa" + "00" * 30, 0)  # P2TR input
        txin2 = TxInput("bbbb" + "00" * 30, 1)  # P2WPKH input

        dest = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")
        txout = TxOutput(to_satoshis(0.00008), dest.to_script_pub_key())

        tx = Transaction([txin1, txin2], [txout], has_segwit=True)
        psbt = PSBT(tx)

        # Update both inputs with UTXOs
        psbt.update_input(
            0, witness_utxo=TxOutput(to_satoshis(0.00005), self.taproot_spk)
        )
        psbt.update_input(
            1, witness_utxo=TxOutput(to_satoshis(0.00005), self.segwit_spk)
        )

        # Sign P2TR input
        psbt.sign_input(0, self.sk1)
        self.assertIsNotNone(psbt.inputs[0].tap_key_sig)
        self.assertEqual(len(psbt.inputs[0].partial_sigs), 0)

        # Sign P2WPKH input
        psbt.sign_input(1, self.sk2)
        self.assertIsNone(psbt.inputs[1].tap_key_sig)
        self.assertEqual(len(psbt.inputs[1].partial_sigs), 1)

        # Finalize both
        psbt.finalize_input(0)
        psbt.finalize_input(1)

        # Extract
        final_tx = psbt.extract_transaction()
        self.assertEqual(len(final_tx.witnesses), 2)

        # P2TR witness: 1 item (sig)
        self.assertEqual(len(psbt.inputs[0].final_scriptwitness), 1)
        # P2WPKH witness: 2 items (sig + pubkey)
        self.assertEqual(len(psbt.inputs[1].final_scriptwitness), 2)


class TestTaprootPSBTWith03Key(unittest.TestCase):
    """Test Taproot PSBT with a key starting with 03 (tests key negation)."""

    def setUp(self):
        setup("testnet")
        # Key that corresponds to pubkey starting with 03
        self.sk = PrivateKey("cNxX8M7XU8VNa5ofd8yk1eiZxaxNrQQyb7xNpwAmsrzEhcVwtCjs")
        self.pub = self.sk.get_public_key()
        self.taproot_addr = self.pub.get_taproot_address()
        self.script_pubkey = self.taproot_addr.to_script_pub_key()

        self.txid = "2a28f8bd8ba0518a86a390da310073a30b7df863d04b42a9c487edf3a8b113af"

    def test_p2tr_03_key_lifecycle(self):
        """Full lifecycle with a key requiring Y-coordinate negation."""
        txin = TxInput(self.txid, 1)
        dest = P2pkhAddress("mtVHHCqCECGwiMbMoZe8ayhJHuTdDbYWdJ")
        txout = TxOutput(to_satoshis(0.00004), dest.to_script_pub_key())
        tx = Transaction([txin], [txout], has_segwit=True)

        psbt = PSBT(tx)
        psbt.update_input(
            0, witness_utxo=TxOutput(to_satoshis(0.00005), self.script_pubkey)
        )

        psbt.sign_input(0, self.sk)
        psbt.finalize_input(0)
        final_tx = psbt.extract_transaction()

        # Compare with direct signing
        direct_tx = Transaction([TxInput(self.txid, 1)], [txout], has_segwit=True)
        sig_hex = self.sk.sign_taproot_input(
            direct_tx, 0, [self.script_pubkey], [to_satoshis(0.00005)]
        )
        direct_tx.witnesses.append(TxWitnessInput([sig_hex]))

        self.assertEqual(final_tx.get_txid(), direct_tx.get_txid())
        self.assertEqual(final_tx.serialize(), direct_tx.serialize())


class TestBIP371Validation(unittest.TestCase):
    """Test BIP-371 field validation during deserialization."""

    def setUp(self):
        setup("testnet")

    def test_invalid_tap_key_sig_length(self):
        """Reject tap_key_sig that is not 64 or 65 bytes."""
        txin = TxInput("aa" * 32, 0)
        txout = TxOutput(to_satoshis(0.00004), Script(["OP_1", "bb" * 32]))
        tx = Transaction([txin], [txout], has_segwit=True)
        psbt = PSBT(tx)

        # Manually set invalid sig, serialize, and try to parse
        psbt.inputs[0].tap_key_sig = b"\x00" * 63  # invalid: 63 bytes

        # The serialization will happen fine, but deserialization should fail
        raw = psbt.to_bytes()
        with self.assertRaises(ValueError) as ctx:
            PSBT.from_bytes(raw)
        self.assertIn("tap_key_sig", str(ctx.exception))

    def test_invalid_tap_internal_key_length(self):
        """Reject tap_internal_key that is not 32 bytes."""
        txin = TxInput("aa" * 32, 0)
        txout = TxOutput(to_satoshis(0.00004), Script(["OP_1", "bb" * 32]))
        tx = Transaction([txin], [txout], has_segwit=True)
        psbt = PSBT(tx)

        psbt.inputs[0].tap_internal_key = b"\x00" * 31  # invalid: 31 bytes

        raw = psbt.to_bytes()
        with self.assertRaises(ValueError) as ctx:
            PSBT.from_bytes(raw)
        self.assertIn("tap_internal_key", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
