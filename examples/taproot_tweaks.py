from decimal import Decimal

from bitcoinutils.keys import PrivateKey, P2trAddress, PublicKey
from bitcoinutils.setup import setup
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.utils import to_satoshis


def main():
    setup("testnet")  # testnet or mainnet

    master_priv = PrivateKey(secret_exponent=4246750693002387237707445190615077334781271705521429522889054373580967716448)
    master_pub = PublicKey.from_hex(master_priv.get_public_key().to_hex())
    print("Mater Publickey", master_pub.get_taproot_address().to_string())

    salt = 1
    salt_bytes = salt.to_bytes(8, byteorder='big')
    tweaked_address = master_pub.get_taproot_address(salt_bytes)
    print("Tweaked Publickey", tweaked_address.to_string())
    # ------ transaction ------

    # UTXO of fromAddress
    utxo_amount = to_satoshis(Decimal('0.00005'))
    amounts = [utxo_amount,]

    script_pubkey = tweaked_address.to_script_pub_key()
    utxos_script_pubkeys = [script_pubkey, ]
    toAddress = P2trAddress("tb1p48a8x62eny909e65mvwvvwgjyz84ggzg4m6uhq53sjjxx0a7exps7nujcy")

    # create transaction input from tx id of UTXO
    txin = TxInput('74bf659ed2e8144ce4d278ff9daf04c181292dd4db9753656f481d0dbad9628b', 1)

    # create transaction output
    send_amount = 1000
    fee_amount = 212 # calculate it from transaction size
    txOut1 = TxOutput(send_amount, toAddress.to_script_pub_key())
    txOut2 = TxOutput(utxo_amount - send_amount - fee_amount, tweaked_address.to_script_pub_key())

    # sign transaction input
    tx = Transaction([txin,], [txOut1, txOut2], has_segwit=True)
    sig = master_priv.sign_taproot_input(tx, 0, utxos_script_pubkeys, amounts, tapleaf_scripts=salt_bytes)
    tx.witnesses.append(TxWitnessInput([sig]))
    print("\nRaw signed transaction:\n" + tx.serialize())

if __name__ == '__main__':
    main()