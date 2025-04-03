# Copyright (C) 2018-2024 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

from binascii import unhexlify
from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import P2pkhAddress, PrivateKey, P2trAddress
from bitcoinutils.script import Script


def main():
    try:
        # always remember to setup the network
        setup("testnet")

        # the key that corresponds to the P2WPKH address
        #priv = PrivateKey("cPiTDzdpEfCwotToidTcNjh4WsdTZRLkYYScs1vHXT4Dzncwasdo")
        priv = PrivateKey(b=unhexlify("3fa9909fad4c01625adc47639626877073d94ead84e9630a66b731776cb66fcf"))
        print(f"internal priv key: {priv.to_bytes().hex()}")

        pub = priv.get_public_key()

        fromAddress = pub.get_taproot_address()
        print(fromAddress.to_string())

        # UTXO of fromAddress
        txid = "bf0dc482d03fd2b57fb97cefd84de42f0bf370930856785e8ec9c019f1fb3aca"
        vout = 0

        # all amounts are needed to sign a taproot input
        # (depending on sighash)
        first_amount = to_satoshis(0.00385004)
        amounts = [first_amount]

        # all scriptPubKeys are needed to sign a taproot input
        # (depending on sighash) but always of the spend input
        first_script_pubkey = fromAddress.to_script_pub_key()

        script_pubkey02 = Script(["OP_1", pub.to_taproot_hex()[0]])
        print(f"first_script_pubkey: {first_script_pubkey.to_hex()}")
        print(f"script_pubkey02: {script_pubkey02.to_hex()}")

        # alternatively:
        # first_script_pubkey = Script(['OP_1', pub.to_taproot_hex()])

        utxos_script_pubkeys = [first_script_pubkey]

        # create transaction input from tx id of UTXO
        seq = "fdffffff"
        txin = TxInput(txid, vout, sequence=seq)

        toAddress1 = P2trAddress("tb1pz38c8e54f6fkfpetmw8j7ft0ft54yeqy7cvzyckwxgjany8vv7vssddyfa")
        toAddress2 = P2trAddress("tb1pdtpkgjvkc77nuzssqh420ulgu3xm88m5vy59wrmgg5ctklkandgqmyh9ah")

        # create transaction output
        txOut1 = TxOutput(to_satoshis(0.00364261), toAddress1.to_script_pub_key())
        txOut2 = TxOutput(to_satoshis(0.00005000 ), toAddress2.to_script_pub_key())
        # create transaction without change output - if at least a single input is
        # segwit we need to set has_segwit=True

        locktime = "a8643400"
        tx = Transaction([txin], [txOut1, txOut2], has_segwit=True, locktime=locktime)

        print("\nRaw transaction:\n" + tx.serialize())

        print("\ntxid: " + tx.get_txid())
        print("\ntxwid: " + tx.get_wtxid())

        # sign taproot input
        # to create the digest message to sign in taproot we need to
        # pass all the utxos' scriptPubKeys and their amounts
        sig = priv.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts)
        # print(sig)

        tx.witnesses.append(TxWitnessInput([sig]))

        # print raw signed transaction ready to be broadcasted
        print("\nRaw signed transaction:\n" + tx.serialize())

        print("\nTxId:", tx.get_txid())
        print("\nTxwId:", tx.get_wtxid())

        print("\nSize:", tx.get_size())
        print("\nvSize:", tx.get_vsize())
    except Exception as e:
      print('Something went wrong', e)
    finally:
      print('The try except is finished')



if __name__ == "__main__":
    main()