from bitcoinutils.keys import P2shAddress, PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.hdwallet import HDWallet
from bitcoinutils.transactions import Transaction, TxInput, TxOutput

setup("testnet")

#
# Send from a P2PKH UTXO and send to P2SH(P2WSH(P2PK))
# Change back to the same address (not recommended for privacy reasons)
#

xprivkey = (
    "tprv8ZgxMBicQKsPdQR9RuHpGGxSnNq8Jr3X4WnT6Nf2eq7FajuXyBep5KWYpYEixxx5XdTm1N"
    "tpe84f3cVcF7mZZ7mPkntaFXLGJD2tS7YJkWU"
)
path = "m/86'/1'/0'/0/1"
hdw = HDWallet(xprivkey, path)
from_priv = hdw.get_private_key()
from_pub = from_priv.get_public_key()
from_addr = from_pub.get_address()
print("From address:", from_addr.to_string())

hdw.from_path("m/86'/1'/0'/0/20")
to_priv = hdw.get_private_key()
to_pub = to_priv.get_public_key()

witness_script = Script([to_pub.to_hex(), "OP_CHECKSIG"])
p2sh_redeem_script = witness_script.to_p2wsh_script_pub_key()  # maybe to_p2sh_...

p2sh_address = P2shAddress.from_script(p2sh_redeem_script)
print("To address:", p2sh_address.to_string())

# UTXO's info
txid = "d4616b3050d2a0fac4783cd9a8c727aafa7b1374098d049e91ecc66d655e79e7"
vout = 0

txin = TxInput(txid, vout)
txout = TxOutput(5000, p2sh_redeem_script.to_p2sh_script_pub_key())
txout_change = TxOutput(1530000, from_addr.to_script_pub_key())
tx = Transaction([txin], [txout, txout_change])

sig = from_priv.sign_input(tx, 0, from_addr.to_script_pub_key())

txin.script_sig = Script([sig, from_pub.to_hex()])

signed_tx = tx.serialize()

print(signed_tx)
