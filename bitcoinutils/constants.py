
NETWORK_WIF_PREFIXES = { 'mainnet': b'\x80',
                         'testnet': b'\xef' }

NETWORK_P2PKH_PREFIXES = { 'mainnet': b'\x00',
                           'testnet': b'\x6f' }

NETWORK_P2SH_PREFIXES = { 'mainnet': b'\x05',
                          'testnet': b'\xc4' }

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
