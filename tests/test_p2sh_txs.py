import unittest

from context import bitcoinutils
from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, P2pkhAddress, P2shAddress
from bitcoinutils.constants import SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY
from bitcoinutils.transactions import TxInput, TxOutput, Transaction
from bitcoinutils.script import Script

class TestCreateP2shTransaction(unittest.TestCase):
    def setUp(self):
        setup('testnet')
        # values for testing sighash single and sighash all/none/single with
        # anyonecanpay
        self.txin = TxInput("76464c2b9e2af4d63ef38a77964b3b77e629dddefc5cb9eb1a3645b1608b790f", 0)
        self.from_addr = P2pkhAddress('n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR')
        self.sk = PrivateKey('cTALNpTpRbbxTCJ2A5Vq88UxT44w1PE2cYqiB3n4hRvzyCev1Wwo')
        self.p2pk_sk = PrivateKey('cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9')
        self.p2pk_redeem_script = Script([self.p2pk_sk.get_public_key().to_hex(),
                                          'OP_CHECKSIG'])
        self.txout = TxOutput( 0.09, self.p2pk_redeem_script.to_p2sh_script_pub_key() )
        self.create_p2sh_and_send_result = '02000000010f798b60b145361aebb95cfcdedd29e6773b4b96778af33ed6f42a9e2b4c4676000000006b483045022100fd3a3fd4aeec5db0f3f9c5c5ef7f60f37920be7464a80edacbc3b6b9d0624173022031ce309330e60b19d39cec8c5597460c840adcdd66f7dbbf896eef3ec42b472f012102d82c9860e36f15d7b72aa59e29347f951277c21cd4d34822acdeeadbcff8a546ffffffff01405489000000000017a9142910fc0b1b7ab6c9789c5a67c22c5bcde5b903908700000000'

        self.txin_spend = TxInput('7db363d5a7fabb64ccce154e906588f1936f34481223ea8c1f2c935b0a0c945b', 0)
        # self.p2pk_sk , self.p2pk_redeem_script from above
        self.to_addr = self.from_addr
        self.txout2 = TxOutput( 0.08, self.to_addr.to_script_pub_key() )
        self.spend_p2sh_result = '02000000015b940c0a5b932c1f8cea231248346f93f18865904e15cecc64bbfaa7d563b37d000000006c47304402204984c2089bf55d5e24851520ea43c431b0d79f90d464359899f27fb40a11fbd302201cc2099bfdc18c3a412afb2ef1625abad8a2c6b6ae0bf35887b787269a6f2d4d01232103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708acffffffff0100127a00000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac00000000'

    def test_signed_send_to_p2sh(self):
        tx = Transaction([self.txin], [self.txout])
        sig = self.sk.sign_input( tx, 0, self.from_addr.to_script_pub_key() )
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = Script([sig, pk])
        self.assertEqual(tx.serialize(), self.create_p2sh_and_send_result)

    def test_spend_p2sh(self):
        tx = Transaction([self.txin_spend], [self.txout2])
        sig = self.p2pk_sk.sign_input(tx, 0, self.p2pk_redeem_script )
        self.txin_spend.script_sig = Script([sig, self.p2pk_redeem_script.to_hex()])
        self.assertEqual(tx.serialize(), self.spend_p2sh_result)

if __name__ == '__main__':
    unittest.main()


