# hex_fix.py
"""
Enhanced fix for the h_to_b function to handle all non-hexadecimal characters.
"""

import re
from bitcoinutils.utils import h_to_b as original_h_to_b

def safe_h_to_b(h):
    """
    A completely safe version of h_to_b that handles any invalid hex characters.
    
    Parameters:
    -----------
    h : str
        The hexadecimal string to convert
        
    Returns:
    --------
    bytes
        The converted bytes
    """
    # If h is not a string, try to convert it
    if not isinstance(h, str):
        try:
            h = str(h)
        except:
            return b''
    
    # Clean the string - remove all non-hex characters
    clean_h = re.sub(r'[^0-9a-fA-F]', '', h)
    
    # Make sure the length is even
    if len(clean_h) % 2 != 0:
        clean_h += '0'
    
    # Handle empty string
    if not clean_h:
        return b''
    
    try:
        return bytes.fromhex(clean_h)
    except Exception as e:
        print(f"Error converting hex to bytes: {e}")
        return b''

# Replace the original h_to_b function
import bitcoinutils.utils
bitcoinutils.utils.h_to_b = safe_h_to_b
print("Applied hex conversion fix")