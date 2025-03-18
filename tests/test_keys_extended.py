from bitcoinutils.setup import setup
from bitcoinutils.keys import PrivateKey, PublicKey
from bitcoinutils.utils import b_to_h, hash160

def test_private_key_generation():
    setup('mainnet')
    priv = PrivateKey()
    assert len(priv.key.to_string()) == 32  # Fixed: Use to_string() to get key bytes

def test_p2wpkh_address_generation():
    setup('mainnet')
    priv = PrivateKey()
    pub = priv.get_public_key()
    hash160_pub = hash160(pub.to_string())  # Ensure pubkey is in bytes
    address = pub.get_segwit_address()
    assert address.to_string().startswith('bc1')

def test_sign_and_verify():
    setup('mainnet')
    priv = PrivateKey()
    pub = priv.get_public_key()
    message = "Test message"
    signature = priv.sign_message(message)
    if signature is None:
        print("Error: sign_message returned None")
        assert False
    assert pub.verify_message(message, signature)

def test_p2pkh_address_generation():
    setup('mainnet')  # Fixed: Set network to mainnet
    priv = PrivateKey()
    pub = priv.get_public_key()
    address = pub.get_address()
    assert address.to_string().startswith('1')