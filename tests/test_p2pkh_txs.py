import unittest

from context import bitcoinutils
from bitcoinutils.setup import setup #, get_network
from bitcoinutils.keys import PrivateKey, Address #, PublicKey
from bitcoinutils.transactions import TxInput, TxOutput, Transaction

class TestCreateP2pkhTransaction(unittest.TestCase):
    def setUp(self):
        setup('testnet')
        self.txin = TxInput('fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c', 0)
        self.addr = Address('n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR')
        self.txout = TxOutput(0.1, ['OP_DUP', 'OP_HASH160', self.addr.to_hash160(), 
                                    'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        self.change_addr = Address('mytmhndz4UbEMeoSZorXXrLpPfeoFUDzEp')
        self.change_low_s_addr = Address('mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w')
        self.change_txout = TxOutput(0.29, ['OP_DUP', 'OP_HASH160',
                                            self.change_addr.to_hash160(),
                                            'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        self.change_low_s_txout = TxOutput(0.29, ['OP_DUP', 'OP_HASH160',
                                            self.change_low_s_addr.to_hash160(),
                                            'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        self.sk = PrivateKey('cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9')
        self.from_addr = Address('myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e')
        self.core_tx_result = '02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb0000000000ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac4081ba01000000001976a914c992931350c9ba48538003706953831402ea34ea88ac00000000'
        self.core_tx_signed_result = '02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb000000006a473044022079dad1afef077fa36dcd3488708dd05ef37888ef550b45eb00cdb04ba3fc980e02207a19f6261e69b604a92e2bffdf6ddbed0c64f55d5003e9dfb58b874b07aef3d7012103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac4081ba01000000001976a914c992931350c9ba48538003706953831402ea34ea88ac00000000'
        self.core_tx_signed_low_s_result = '02000000016cce96ffe999c7b2abc8b7bebec0c821e9c378ac41417106f6ddf63be2f448fb000000006a473044022044ef433a24c6010a90af14f7739e7c60ce2c5bc3eab96eaee9fbccfdbb3e272202205372a617cb235d0a0ec2889dbfcadf15e10890500d184c8dda90794ecdf79492012103a2fef1829e0742b89c218c51898d9e7cb9d51201ba2bf9d9e9214ebb6af32708ffffffff0280969800000000001976a914fd337ad3bf81e086d96a68e1f8d6a0a510f8c24a88ac4081ba01000000001976a91442151d0c21442c2b038af0ad5ee64b9d6f4f4e4988ac00000000'

    def test_unsigned_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_txout])
        self.assertEqual(tx.serialize(), self.core_tx_result)

    def test_signed_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_txout])
        unsigned_tx = tx.serialize()
        sig = self.sk.sign_input(tx, 0, ['OP_DUP', 'OP_HASH160',
                                         self.from_addr.to_hash160(),
                                         'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = [sig, pk]
        self.assertEqual(tx.serialize(), self.core_tx_signed_result)

    def test_signed_low_s_tx_1_input_2_outputs(self):
        tx = Transaction([self.txin], [self.txout, self.change_low_s_txout])
        unsigned_tx = tx.serialize()
        sig = self.sk.sign_input(tx, 0, ['OP_DUP', 'OP_HASH160',
                                         self.from_addr.to_hash160(),
                                         'OP_EQUALVERIFY', 'OP_CHECKSIG'])
        pk = self.sk.get_public_key().to_hex()
        self.txin.script_sig = [sig, pk]
        self.assertEqual(tx.serialize(), self.core_tx_signed_low_s_result)



if __name__ == '__main__':
    unittest.main()


