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


from bitcoinutils.setup import setup
from bitcoinutils.utils import to_satoshis
from bitcoinutils.transactions import (
    Transaction,
    TxInput,
    TxOutput,
    TxWitnessInput,
    Locktime,
)
from bitcoinutils.keys import P2pkhAddress, PrivateKey
from bitcoinutils.script import Script


def test_non_segwit():
    # always remember to setup the network
    setup("testnet")

    # create transaction input from tx id of UTXO (contained 0.4 tBTC)
    txin = TxInput(
        "fb48f4e23bf6ddf606714141ac78c3e921c8c0bebeb7c8abb2c799e9ff96ce6c", 0
    )

    # create transaction output using P2PKH scriptPubKey (locking script)
    addr = P2pkhAddress("n4bkvTyU1dVdzsrhWBqBw8fEMbHjJvtmJR")
    txout = TxOutput(
        to_satoshis(0.1),
        Script(
            ["OP_DUP", "OP_HASH160", addr.to_hash160(), "OP_EQUALVERIFY", "OP_CHECKSIG"]
        ),
    )

    # create another output to get the change - remaining 0.01 is tx fees
    # note that this time we used to_script_pub_key() to create the P2PKH
    # script
    change_addr = P2pkhAddress("mmYNBho9BWQB2dSniP1NJvnPoj5EVWw89w")
    change_txout = TxOutput(to_satoshis(0.29), change_addr.to_script_pub_key())
    # change_txout = TxOutput(to_satoshis(0.29), Script(['OP_DUP', 'OP_HASH160',
    #                                     change_addr.to_hash160(),
    #                                     'OP_EQUALVERIFY', 'OP_CHECKSIG']))

    # create transaction from inputs/outputs/locktime
    tx = Transaction(
        [txin], [txout, change_txout], Locktime(552203117).for_transaction()
    )

    print("\nUnsigned transaction:", tx)
    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())
    tx_from_raw = Transaction.from_raw(tx.serialize())
    print("\nUnsigned from raw transaction:", tx_from_raw)
    print("\nUnsigned from raw transaction raw:", tx_from_raw.serialize())

    if tx_from_raw.serialize() == tx.serialize():
        print("SUCCESS from_raw Serialization OK")
    else:
        print("ERROR from_raw Serialization failed")

    if str(tx) == str(tx_from_raw):
        print("SUCCESS from_raw OK")
    else:
        print("ERROR from_raw failed")

    # use the private key corresponding to the address that contains the
    # UTXO we are trying to spend to sign the input
    sk = PrivateKey("cRvyLwCPLU88jsyj94L7iJjQX5C2f8koG4G2gevN4BeSGcEvfKe9")

    # note that we pass the scriptPubkey as one of the inputs of sign_input
    # because it is used to replace the scriptSig of the UTXO we are trying to
    # spend when creating the transaction digest
    from_addr = P2pkhAddress("myPAE9HwPeKHh8FjKwBNBaHnemApo3dw6e")
    sig = sk.sign_input(
        tx,
        0,
        Script(
            [
                "OP_DUP",
                "OP_HASH160",
                from_addr.to_hash160(),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ]
        ),
    )
    # print(sig)

    # get public key as hex
    pk = sk.get_public_key().to_hex()

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, pk])
    signed_tx = tx.serialize()

    print("\nSigned transaction:", tx)
    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:", signed_tx)
    tx_from_raw = Transaction.from_raw(tx.serialize())
    print("\nSigned from raw transaction:", tx_from_raw)
    print("\nSigned from raw transaction raw:", tx_from_raw.serialize())

    if tx_from_raw.serialize() == tx.serialize():
        print("SUCCESS signed from_raw Serialization OK")
    else:
        print("ERROR signed from_raw Serialization failed")

    if str(tx) == str(tx_from_raw):
        print("SUCCESS signed from_raw OK")
    else:
        print("ERROR signed from_raw failed")


def test_segwit():
    setup("testnet")

    # the key that corresponds to the P2WPKH address
    priv = PrivateKey("cVdte9ei2xsVjmZSPtyucG43YZgNkmKTqhwiUA8M4Fc3LdPJxPmZ")

    pub = priv.get_public_key()

    fromAddress = pub.get_segwit_address()
    print(fromAddress.to_string())

    # amount is needed to sign the segwit input
    fromAddressAmount = to_satoshis(0.01)

    # UTXO of fromAddress
    txid = "13d2d30eca974e8fa5da11b9608fa36905a22215e8df895e767fc903889367ff"
    vout = 0

    toAddress = P2pkhAddress("mrrKUpJnAjvQntPgz2Z4kkyr1gbtHmQv28")

    # create transaction input from tx id of UTXO
    txin = TxInput(txid, vout)

    # the script code required for signing for p2wpkh is the same as p2pkh
    script_code = Script(
        ["OP_DUP", "OP_HASH160", pub.to_hash160(), "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )

    # create transaction output
    txOut = TxOutput(to_satoshis(0.009), toAddress.to_script_pub_key())

    # create transaction without change output - if at least a single input is
    # segwit we need to set has_segwit=True
    tx = Transaction(
        [txin],
        [txOut],
        Locktime(552203117).for_transaction(),
    )

    print("\nUnsigned transaction:", tx)
    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())
    tx_from_raw = Transaction.from_raw(tx.serialize())
    print("\nUnsigned from raw transaction:", tx_from_raw)
    print("\nUnsigned from raw transaction raw:", tx_from_raw.serialize())

    if tx_from_raw.serialize() == tx.serialize():
        print("SUCCESS from_raw Serialization OK")
    else:
        print("ERROR from_raw Serialization failed")

    if str(tx) == str(tx_from_raw):
        print("SUCCESS from_raw OK")
    else:
        print("ERROR from_raw failed")

    sig = priv.sign_segwit_input(tx, 0, script_code, fromAddressAmount)

    # note that TxWitnessInput gets a list of witness items (not script opcodes)
    tx.witnesses.append(TxWitnessInput([sig, pub.to_hex()]))
    tx.has_segwit = True

    # print raw signed transaction ready to be broadcasted
    print("\nSigned transaction:", tx)
    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:", tx.serialize())
    tx_from_raw = Transaction.from_raw(tx.serialize())
    print("\nSigned from raw transaction:", tx_from_raw)
    print("\nSigned from raw transaction raw:", tx_from_raw.serialize())

    if tx_from_raw.serialize() == tx.serialize():
        print("SUCCESS signed from_raw Serialization OK")
    else:
        print("ERROR signed from_raw Serialization failed")

    if str(tx) == str(tx_from_raw):
        print("SUCCESS signed from_raw OK")
    else:
        print("ERROR signed from_raw failed")


if __name__ == "__main__":
    test_non_segwit()
    test_segwit()
