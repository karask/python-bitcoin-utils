"""
Example: Create a Taproot address with four leaf scripts (4-leaf Merkle tree)

This demonstrates:
- Hashlock using OP_SHA256
- 2-of-2 multisig with CHECKSIGADD
- CSV timelock (relative lock)
- Simple CHECKSIG for fallback

Author: Aaron Zhang (@aaron_recompile)
"""

from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.transactions import Sequence

import hashlib
from bitcoinutils.constants import TYPE_RELATIVE_TIMELOCK



def main():
    setup('testnet')

    # Alice's internal private key (for Taproot address)
    alice_priv = PrivateKey("cNwW6ne3j9jUDWC3qFG5Bw3jzWvSZjZ2vgyP5LsTVj4WrJkJqjuz")
    # Bob's private key, for multisig and CSV timelock script path
    bob_priv = PrivateKey("cMrC8dGmStj3pz7mbY3vjwhXYcQwkcaWwV4QFCTF25WwVW1TCDkJ")

    alice_pub = alice_priv.get_public_key()
    bob_pub = bob_priv.get_public_key()    

    # Script 1: Verify SHA256(preimage) == hash(helloworld)
    hash1 = hashlib.sha256(b"helloworld").hexdigest()
    script1 = Script(['OP_SHA256', hash1, 'OP_EQUALVERIFY', 'OP_TRUE'])

    # Script 2: 2-of-2 multisig (using CHECKSIGADD)
    script2 = Script([
        "OP_0",
        alice_pub.to_x_only_hex(),
        "OP_CHECKSIGADD",
        bob_pub.to_x_only_hex(),
        "OP_CHECKSIGADD",
        "OP_2", 
        "OP_EQUAL"
    ])

    # Script 3: CSV timelock
    relative_blocks = 2 # 2 blocks on testnet3, needs about 20 minutes to unlock
    seq = Sequence(TYPE_RELATIVE_TIMELOCK, relative_blocks)
    script3 = Script([
        seq.for_script(),
        "OP_CHECKSEQUENCEVERIFY",
        "OP_DROP",
        bob_pub.to_x_only_hex(),
        "OP_CHECKSIG"
    ]) 

    # Script 4: Bob's siglock
    script4 = Script([
        bob_pub.to_x_only_hex(),
        "OP_CHECKSIG"
    ])
    print(f"4th script hex: {script4.to_hex()}")        

    # Build Merkle Tree
    tree = [[script1, script2], [script3, script4]]

    # Generate Taproot address
    address = alice_pub.get_taproot_address(tree)
    print("🪙 Please send funds to this Taproot address:", address.to_string())


if __name__ == '__main__':
    main()