from bitcoinutils.transactions import (
    Transaction,
)

from bitcoinutils.utils import (
    encode_varint,
    vi_to_int
)

MAGIC_BYTES = b"psbt\xff"
SEPARATOR = b'\x00'

# Global key types
PSBT_GLOBAL_UNSIGNED_TX = b'\x00'
PSBT_GLOBAL_XPUB = b'\x01'
PSBT_GLOBAL_TX_VERSION = b'\x02'
PSBT_GLOBAL_FALLBACK_LOCKTIME = b'\x03'
PSBT_GLOBAL_INPUT_COUNT = b'\x04'
PSBT_GLOBAL_OUTPUT_COUNT = b'\x05'
PSBT_GLOBAL_TX_MODIFIABLE = b'\x06'
PSBT_GLOBAL_SP_ECDH_SHARE = b'\x07'
PSBT_GLOBAL_SP_DLEQ = b'\x08'
PSBT_GLOBAL_VERSION = b'\xFB'
PSBT_GLOBAL_PROPRIETARY = b'\xFC'

# Per-input key types
PSBT_IN_NON_WITNESS_UTXO = b'\x00'
PSBT_IN_WITNESS_UTXO = b'\x01'
PSBT_IN_PARTIAL_SIG = b'\x02'
PSBT_IN_SIGHASH_TYPE = b'\x03'
PSBT_IN_REDEEM_SCRIPT = b'\x04'
PSBT_IN_WITNESS_SCRIPT = b'\x05'
PSBT_IN_BIP32_DERIVATION = b'\x06'
PSBT_IN_FINAL_SCRIPTSIG = b'\x07'
PSBT_IN_FINAL_SCRIPTWITNESS = b'\x08'

# Per-output key types
PSBT_OUT_REDEEM_SCRIPT = b'\x00'
PSBT_OUT_WITNESS_SCRIPT = b'\x01'
PSBT_OUT_BIP32_DERIVATION = b'\x02'
PSBT_OUT_AMOUNT = b'\x03'
PSBT_OUT_SCRIPT = b'\x04'


class PSBT:
    def __init__(self, maps: dict):
        '''
        Parameters
        ----------
        maps : dict
            A dictionary with the keys 'global', 'input' and 'output' containing the corresponding maps.'''
        self.maps = maps
        #TODO: add checks to validate psbt (will be added in future PRs)

    @staticmethod
    def serialize_key_val(key: bytes, val: bytes):
        '''Serialize a key value pair, key, val should be bytes'''
        return encode_varint(len(key)) + key + encode_varint(len(val)) + val
    
    @staticmethod
    def parse_key_value(s):
        """Parse a key-value pair from the PSBT stream."""
        # Read the first byte to determine the key length
        key_length_bytes = s.read(1)
        key_length, _ = vi_to_int(key_length_bytes)
        # If key length is 0, return None (indicates a separator)
        if key_length == 0:
            return None, None
        # Read the key
        key = s.read(key_length)
        
        # Read the value length
        val_length_bytes = s.read(1)
        val_length, _ = vi_to_int(val_length_bytes)
        # Read the value
        val = s.read(val_length)
        
        return key, val
    
    def serialize(self):
        psbt = MAGIC_BYTES
        for key, val in sorted(self.maps['global'].items()):
            psbt += self.serialize_key_val(key, val)
        psbt += SEPARATOR
        for inp in self.maps['input']:
            for key, val in sorted(inp.items()):
                psbt += self.serialize_key_val(key, val)
            psbt += SEPARATOR
        for out in self.maps['output']:
            for key, val in sorted(out.items()):
                psbt += self.serialize_key_val(key, val)
            psbt += SEPARATOR
        return psbt

    
    @classmethod
    def parse(cls, s):
        if s.read(5) != MAGIC_BYTES:
            raise ValueError('Invalid PSBT magic bytes')
        maps = {'global': {}, 'input': [], 'output': []}

        globals = True #To check if paresed key value is from global map
        input_ind = 0
        output_ind = 0

        while globals or input_ind > 0 or output_ind > 0:
            key, val = PSBT.parse_key_value(s)

            if globals:
                if key is None: #Separator is reached indicating end of global map
                    globals = False
                    continue
                
                maps['global'][key] = val
                
                
                if key == PSBT_GLOBAL_UNSIGNED_TX: #If unsigned transaction is found, intialize input and output maps
                    hex_val = val.hex()
                    transaction = Transaction.from_raw(hex_val)
                    input_ind = len(transaction.inputs)
                    output_ind = len(transaction.outputs)
                    # input_ind = 1
                    # output_ind = 1
                    maps['input'] = [{} for _ in range(input_ind)]
                    maps['output'] = [{} for _ in range(output_ind)]
                
            elif input_ind > 0: # Means input map is being parsed
                if key is None: #Separator is reached; indicating end of the particular input map, there can be multiple input maps
                    input_ind -= 1
                    continue

                ind = input_ind - len(maps['input']) #Get the index of the input being parsed
                maps['input'][ind][key] = val
            
            elif output_ind > 0: # Means output map is being parsed

                if key is None: #Separator is reached; indicating end of the particular output map, there can be multiple output maps
                    output_ind -= 1
                    continue

                ind = output_ind - len(maps['output']) #Get the index of the output being parsed
                maps['output'][ind][key] = val
                
                return cls(maps)
            
    #TODO: Add methods to parse and serialize psbt as b64 and hex (will be added in future PRs)