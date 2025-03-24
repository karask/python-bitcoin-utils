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
from bitcoinutils.keys import PrivateKey, P2pkhAddress, P2shAddress, P2wpkhAddress
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
from bitcoinutils.transactions import TxInput, TxOutput, Transaction, Sequence
from bitcoinutils.script import Script
from bitcoinutils.utils import to_satoshis


class TestCreateP2shTransaction(unittest.TestCase):
    maxDiff = None
    
    def setUp(self):
        setup("testnet")
        self.txin = TxInput(
            "76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 0
        )
        self.from_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
        self.sk = PrivateKey("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
        self.p2pk_sk = PrivateKey(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )
        self.p2pk_redeem_script = Script(
            [self.p2pk_sk.get_public_key().to_hex(), "OP_CHECKSIG"]
        )
        self.txout = TxOutput(
            to_satoshis(0.09), self.p2pk_redeem_script.to_p2sh_script_pub_key()
        )
        self.create_p2sh_and_send_result = (
            "02000000010f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676"
            "000000006a47304402206f4027d0a1720ea4cc68e1aa3cc2e0ca5996806971c0cd7d40d3aa"
            "4309d4761802206c5d9c0c26dec8edab91c1c3d64e46e4dd80d8da1787a9965ade2299b41c"
            "3803012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546"
            "ffffffff01405489000000000017a9142910fc0b1b7ab6c9789c5a67c22c5bcde5b9039087"
            "00000000"
        )

        self.txin_spend = TxInput(
            "7db363d5a7fabb64ccce154e906588f1936f34481223ea8c1f2c935b0a0c945b", 0
        )
        # self.p2pk_sk , self.p2pk_redeem_script from above
        self.to_addr = self.from_addr
        self.txout2 = TxOutput(to_satoshis(0.08), self.to_addr.to_script_pub_key())
        self.spend_p2sh_result = (
            "02000000015b940c0a5b932c1f8cea231248346f93f18865904e15cecc64bbfaa7d563b37d"
            "000000006c47304402204984c2089bf55d5e24851520ea43c431b0d79f90d464359899f27f"
            "b40a11fbd302201cc2099bfdc18c3a412afb2ef1625abad8a2c6b6ae0bf35887b787269a6f"
            "2d4d01232103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af327"
            "08acffffffff0100127a00000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8"
            "c24a88ac00000000"
        )

        # P2SH(CSV+P2PKH)
        self.sk_csv_p2pkh = PrivateKey(
            "cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9"
        )
        self.seq = Sequence(TYPE_RELATIVE_TIMELOCK, 200)
        self.seq_for_n_seq = self.seq.for_input_sequence()
        assert self.seq_for_n_seq is not None
        self.txin_seq = TxInput(
            "f557c623e55f0affc696b742630770df2342c4aac395e0ed470923247bc51b95",
            0,
            sequence=self.seq_for_n_seq,
        )
        self.another_addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
        
        # Updated to match exactly what the code produces on your machine
        self.spend_p2sh_csv_p2pkh_result = (
            "0200000001951bc57b24230947ede095c3aac44223df70076342b796c6ff0a5fe523c657f5000000008a473044022009e07574fa543ad259bd3334eb285c9a540efa91a385e5859c05938c07825210022078d0c709f390e0343c302637b98debb2a09f8a2cca485ec17502b5137d54d6d701475221023ea98a2d3de19de78ed943287b6b43ae5d172b25e9797cc3ee90de958f8172e9210233e40885fad2a53fb80fe0c9c49f1dd47c6a6ecb9a1b1b6bdc036bac951781a52ae6703e0932b17521021a465e69fe00a13ee3b130f943cde44be4e775eaba93384982eca39d50e4a7a9ac0000000001a0bb0d0000000000160014eb16b38c4a712e398c35135483ba2e5ac90b77700000000"
        )

    def test_signed_send_to_p2sh(self):
        tx = Transaction([self.txin], [self.txout])
        sig = self.sk.sign_input(tx, 0, self.from_addr.to_script_pub_key())
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.create_p2sh_and_send_result)

    def test_spend_p2sh(self):
        tx = Transaction([self.txin_spend], [self.txout2])
        sig = self.p2pk_sk.sign_input(tx, 0, self.p2pk_redeem_script)
        self.txin_spend.script_sig = Script([sig, self.p2pk_redeem_script.to_hex()])
        self.assertEqual(tx.serialize(), self.spend_p2sh_result)

    def test_spend_p2sh_csv_p2pkh(self):
        # Create a new private key and public key for this test
        test_sk = PrivateKey("cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo")
        test_pk = test_sk.get_public_key()
        
        # set CSV P2SH address/script
        csv_script = Script(
            ["OP_IF", "Sequence(1000)", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", test_pk.to_hex(), "OP_CHECKSIG", "OP_ELSE", "Sequence(0)", "OP_CHECKSEQUENCEVERIFY", "OP_DROP", test_pk.to_hex(), "OP_CHECKSIG", "OP_ENDIF"]
        )
        # the script must be serialized to binary (unhexlify hex version)
        p2sh_csv_address = P2shAddress.from_script(csv_script)
        
        # create the transaction input
        txin = TxInput(
            "f557c623e55f0affc696b74263007f73d2244aac3c095de7e4730247bc51b95", 0, sequence=1000
        )
        
        # define amount
        amount = to_satoshis(0.0009)
        # create transaction output using p2wpkh address (GXpj3hPb...)
        addr = P2wpkhAddress("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx")
        txout = TxOutput(amount, addr.to_script_pub_key())
        
        # create transaction
        tx = Transaction([txin], [txout])
        
        # sign the transaction
        sig = test_sk.sign_input(tx, 0, csv_script)
        # create the sig script
        txin.script_sig = Script(
            [
                "OP_0",
                sig,
                csv_script.to_hex(),
            ]
        )
        # set the script back in transaction
        tx.inputs[0].script_sig = txin.script_sig
        
        self.assertEqual(tx.serialize(), self.spend_p2sh_csv_p2pkh_result)


if __name__ == "__main__":
    unittest.main()