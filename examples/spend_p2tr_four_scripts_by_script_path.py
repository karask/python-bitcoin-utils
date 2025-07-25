"""
Example: Spend from a 4-leaf Taproot address via Script Path (Hashlock, Multisig, CSV, or Siglock)

Merkle Tree Layout:
         Merkle Root
         /        \
    Branch0      Branch1  
   /      \      /      \
S0       S1     S2      S3
Hashlock Multi  CSV     Siglock

This script allows spending from any of the four script paths using the correct ControlBlock and Witness stack.

Author: Aaron Zhang (@aaron_recompile)
"""

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput, Sequence
from bitcoinutils.utils import to_satoshis, ControlBlock
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK
import hashlib

def get_leaf_scripts(alice_pub, bob_pub):
    preimage = "helloworld"
    hashlock_script = Script([
        'OP_SHA256',
        hashlib.sha256(preimage.encode()).hexdigest(),
        'OP_EQUALVERIFY',
        'OP_TRUE'
    ])

    multisig_script = Script([
        'OP_0',
        alice_pub.to_x_only_hex(),
        'OP_CHECKSIGADD',
        bob_pub.to_x_only_hex(),
        'OP_CHECKSIGADD',
        'OP_2',
        'OP_EQUAL'
    ])

    seq = Sequence(TYPE_RELATIVE_TIMELOCK, 2)
    csv_script = Script([
        seq.for_script(),
        'OP_CHECKSEQUENCEVERIFY',
        'OP_DROP',
        bob_pub.to_x_only_hex(),
        'OP_CHECKSIG'
    ])

    sig_script = Script([
        bob_pub.to_x_only_hex(),
        'OP_CHECKSIG'
    ])

    return [hashlock_script, multisig_script, csv_script, sig_script], preimage

def main():
    setup('testnet')

    alice_priv = PrivateKey("cNwW6ne3j9jUDWC3qFG5Bw3jzWvSZjZ2vgyP5LsTVj4WrJkJqjuz")
    bob_priv = PrivateKey("cMrC8dGmStj3pz7mbY3vjwhXYcQwkcaWwV4QFCTF25WwVW1TCDkJ")

    alice_pub = alice_priv.get_public_key()
    bob_pub = bob_priv.get_public_key()

    scripts, preimage = get_leaf_scripts(alice_pub, bob_pub)
    tree = [[scripts[0], scripts[1]], [scripts[2], scripts[3]]]
    taproot_address = alice_pub.get_taproot_address(tree)
    print("Taproot address:", taproot_address.to_string())

    leaf_index = 3  # Input the index of the script to spend
    tapleaf_script = scripts[leaf_index]
 
    ctrl_block = ControlBlock(
        alice_pub,
        tree,
        leaf_index,
        is_odd=taproot_address.is_odd()
    )

    # Input your UTXO info here
    prev_txid = "bd46ceabbe7cc0f2083cc58fc165daf8469d87b23795a1add3a7df78edfa639c"
    vout = 1
    input_amount = 6858
    output_amount = 666
    fee = 400
    change_amount = input_amount - output_amount - fee

    # Input your receiver address here
    receiver_address = "tb1p647tfurqxqauaae4klwkwsaljn7yueg2692hasmp4a082cdtm4yqk2895f"

    # Create transaction inputs and outputs
    txin = TxInput(prev_txid, vout)
    
    # Create Script objects for both outputs
    from bitcoinutils.keys import P2trAddress
    receiver_script = P2trAddress(receiver_address).to_script_pub_key()
    txout1 = TxOutput(output_amount, receiver_script)
    txout2 = TxOutput(change_amount, taproot_address.to_script_pub_key())  # change back to same Taproot
    tx = Transaction([txin], [txout1, txout2], has_segwit=True)

    # Handle different script paths based on leaf_index
    if leaf_index == 0:
        # Hashlock script path
        preimage_hex = preimage.encode('utf-8').hex()
        witness = TxWitnessInput([
            preimage_hex,
            tapleaf_script.to_hex(),
            ctrl_block.to_hex()
        ])
    elif leaf_index == 1:
        # Multisig script path
        sigB = bob_priv.sign_taproot_input(
            tx, 0,
            [taproot_address.to_script_pub_key()],
            [input_amount],
            script_path=True,
            tapleaf_script=tapleaf_script,
            tweak=False
        )
        sigA = alice_priv.sign_taproot_input(
            tx, 0,
            [taproot_address.to_script_pub_key()],
            [input_amount],
            script_path=True,
            tapleaf_script=tapleaf_script,
            tweak=False
        )
        witness = TxWitnessInput([
            sigB, sigA,
            tapleaf_script.to_hex(),
            ctrl_block.to_hex()
        ])
    elif leaf_index == 2:
        # CSV timelock script path - need to set sequence
        seq = Sequence(TYPE_RELATIVE_TIMELOCK, 2)
        seq_for_n_seq = seq.for_input_sequence()
        assert seq_for_n_seq is not None
        txin.sequence = seq_for_n_seq
        
        sig = bob_priv.sign_taproot_input(
            tx, 0,
            [taproot_address.to_script_pub_key()],
            [input_amount],
            script_path=True,
            tapleaf_script=tapleaf_script,
            tweak=False
        )
        witness = TxWitnessInput([
            sig,
            tapleaf_script.to_hex(),
            ctrl_block.to_hex()
        ])
    elif leaf_index == 3:
        # Simple siglock script path
        sig = bob_priv.sign_taproot_input(
            tx, 0,
            [taproot_address.to_script_pub_key()],
            [input_amount],
            script_path=True,
            tapleaf_script=tapleaf_script,
            tweak=False
        )
        witness = TxWitnessInput([
            sig,
            tapleaf_script.to_hex(),
            ctrl_block.to_hex()
        ])
    else:
        raise Exception("Invalid leaf index")

    tx.witnesses.append(witness)

    print("Final transaction (raw):")
    print(tx.serialize())

if __name__ == "__main__":
    main()