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
from bitcoinutils.transactions import Transaction, TxInput, TxOutput
from bitcoinutils.keys import P2pkhAddress, PrivateKey
from bitcoinutils.script import Script


#
# Note that a non-standard transaction can only be included in a block if a
# miner agrees with it. For this to work one needs to use a node setup up
# for regtest so that you can mine your own blocks; unless you mine your own
# testnet/mainnet blocks.
# Node's config file requires:
#    regtest=1
#    acceptnonstdtxn=1
#
def main():
    # always remember to setup the network
    setup("regtest")

    # create transaction input from tx id of UTXO (contained 0.4 tBTC)
    txin = TxInput(
        "e2d08a63a540000222d6a92440436375d8b1bc89a2638dc5366833804287c83f", 1
    )

    # locking script expects 2 numbers that when added equal 5 (silly example)
    txout = TxOutput(to_satoshis(0.9), Script(["OP_ADD", "OP_5", "OP_EQUAL"]))

    # create another output to get the change - remaining 0.01 is tx fees
    # note that this time we used to_script_pub_key() to create the P2PKH
    # script
    change_addr = P2pkhAddress("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
    change_txout = TxOutput(to_satoshis(2), change_addr.to_script_pub_key())

    # create transaction from inputs/outputs -- default locktime is used
    tx = Transaction([txin], [txout, change_txout])

    # print raw transaction
    print("\nRaw unsigned transaction:\n" + tx.serialize())

    # use the private key corresponding to the address that contains the
    # UTXO we are trying to spend to sign the input
    sk = PrivateKey("cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN87JcbXMTcA")

    # note that we pass the scriptPubkey as one of the inputs of sign_input
    # because it is used to replace the scriptSig of the UTXO we are trying to
    # spend when creating the transaction digest
    from_addr = P2pkhAddress("mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r")
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
    pk = sk.get_public_key()
    pk = pk.to_hex()
    # print (pk)

    # set the scriptSig (unlocking script)
    txin.script_sig = Script([sig, pk])
    signed_tx = tx.serialize()

    # print raw signed transaction ready to be broadcasted
    print("\nRaw signed transaction:\n" + signed_tx)


if __name__ == "__main__":
    main()
