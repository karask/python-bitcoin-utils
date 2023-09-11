from bitcoinutils.keys import P2shAddress, PrivateKey
from bitcoinutils.script import Script
from bitcoinutils.setup import setup
from bitcoinutils.hdwallet import HDWallet
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput

setup("testnet")

#
# Send from a P2SH(P2WSH(P2PK)) UTXO to a P2PKH UTXO
#

xprivkey = (
    "tprv8ZgxMBicQKsPdQR9RuHpGGxSnNq8Jr3X4WnT6Nf2eq7FajuXyBep5KWYpYEixxx5XdTm1N"
    "tpe84f3cVcF7mZZ7mPkntaFXLGJD2tS7YJkWU"
)
path = "m/86'/1'/0'/0/20"
hdw = HDWallet(xprivkey, path)
from_priv = hdw.get_private_key()
print(from_priv.to_wif())
from_pub = from_priv.get_public_key()
from_addr = from_pub.get_address()

witness_script = Script([from_pub.to_hex(), "OP_CHECKSIG"])
p2sh_redeem_script = witness_script.to_p2wsh_script_pub_key()
print("From address:", P2shAddress.from_script(p2sh_redeem_script).to_string())

hdw.from_path("m/86'/1'/0'/0/25")
to_priv = hdw.get_private_key()
to_address = to_priv.get_public_key().get_address()
print("To address:", to_address.to_string())

# UTXO's info
txid = "217f123726bd8ace101afd705ae31384fd818fce17c8e00ce6fc0d24c0364355"
vout = 0
amount = 5000

txin = TxInput(txid, vout)
txout = TxOutput(3000, to_address.to_script_pub_key())
tx = Transaction([txin], [txout], has_segwit=True)

sig = from_priv.sign_segwit_input(tx, 0, witness_script, amount)

txin.script_sig = Script([p2sh_redeem_script.to_hex()])
tx.witnesses.append(TxWitnessInput([sig, witness_script.to_hex()]))

signed_tx = tx.serialize()

print(signed_tx)
