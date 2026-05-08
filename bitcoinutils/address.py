# Copyright (C) 2018-2025 The python-bitcoin-utils developers
#
# This file is part of python-bitcoin-utils
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoin-utils, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from typing import Optional, Union, Literal, Type, Any

from bitcoinutils.constants import (
    P2PKH_ADDRESS, P2SH_ADDRESS, P2WPKH_ADDRESS_V0, P2WSH_ADDRESS_V0, P2TR_ADDRESS_V1
)
from bitcoinutils.keys import (
    Address, P2pkhAddress, P2shAddress, SegwitAddress, P2wpkhAddress, P2wshAddress, P2trAddress
)
from bitcoinutils.script import Script

AddressType = Literal[
    "p2pkh", "p2sh", "p2wpkhv0", "p2wshv0", "p2trv1"
]

AddressClass = Union[
    Type[P2pkhAddress], Type[P2shAddress], Type[P2wpkhAddress], Type[P2wshAddress], Type[P2trAddress]
]

AddressInstance = Union[
    P2pkhAddress, P2shAddress, P2wpkhAddress, P2wshAddress, P2trAddress
]


class UnifiedAddress:
    """Unified Bitcoin address class that can handle all address types and conversions.
    
    This class wraps the existing address classes and provides conversion methods
    between different address types.
    
    Attributes
    ----------
    address : AddressInstance
        The wrapped address object
    address_type : str
        The type of address (p2pkh, p2sh, p2wpkhv0, p2wshv0, p2trv1)
    
    Methods
    -------
    from_address(address_str, address_type=None)
        Creates a UnifiedAddress from an address string (classmethod)
    from_script(script, address_type="p2sh")
        Creates a UnifiedAddress from a script (classmethod)
    from_hash160(hash_str, address_type="p2pkh")
        Creates a UnifiedAddress from a hash160 string (classmethod)
    from_witness_program(witness_program, address_type="p2wpkhv0")
        Creates a UnifiedAddress from a witness program (classmethod)
    to_script_pub_key()
        Returns the script pubkey for the address
    to_address_type(address_type)
        Converts the address to a different type if possible
    to_string()
        Returns the address as a string
    """
    
    def __init__(self, address: AddressInstance):
        """Initialize with an existing address object.
        
        Parameters
        ----------
        address : AddressInstance
            An instance of one of the address classes
        """
        self.address = address
        self.address_type = address.get_type()
    
    @classmethod
    def from_address(cls, address_str: str, address_type: Optional[AddressType] = None) -> 'UnifiedAddress':
        """Create a UnifiedAddress from an address string.
        
        Parameters
        ----------
        address_str : str
            The address string
        address_type : str, optional
            The type of address if known (otherwise will be auto-detected)
            
        Returns
        -------
        UnifiedAddress
            A new UnifiedAddress object
            
        Raises
        ------
        ValueError
            If the address is invalid
        """
        # Auto-detect address type if not provided
        if address_type is None:
            address_type = cls._detect_address_type(address_str)
        
        # Create address object based on type
        if address_type == P2PKH_ADDRESS:
            address = P2pkhAddress(address=address_str)
        elif address_type == P2SH_ADDRESS:
            address = P2shAddress(address=address_str)
        elif address_type == P2WPKH_ADDRESS_V0:
            address = P2wpkhAddress(address=address_str)
        elif address_type == P2WSH_ADDRESS_V0:
            address = P2wshAddress(address=address_str)
        elif address_type == P2TR_ADDRESS_V1:
            address = P2trAddress(address=address_str)
        else:
            raise ValueError(f"Unsupported address type: {address_type}")
        
        return cls(address)
    
    @classmethod
    def from_script(cls, script: Script, address_type: AddressType = P2SH_ADDRESS) -> 'UnifiedAddress':
        """Create a UnifiedAddress from a script.
        
        Parameters
        ----------
        script : Script
            The script
        address_type : str, optional
            The type of address to create (default is P2SH)
            
        Returns
        -------
        UnifiedAddress
            A new UnifiedAddress object
            
        Raises
        ------
        ValueError
            If the address type is not supported for scripts
        """
        if address_type == P2SH_ADDRESS:
            address = P2shAddress(script=script)
        elif address_type == P2WSH_ADDRESS_V0:
            address = P2wshAddress(script=script)
        else:
            raise ValueError(f"Cannot create {address_type} directly from script")
        
        return cls(address)
    
    @classmethod
    def from_hash160(cls, hash_str: str, address_type: AddressType = P2PKH_ADDRESS) -> 'UnifiedAddress':
        """Create a UnifiedAddress from a hash160 string.
        
        Parameters
        ----------
        hash_str : str
            The hash160 hex string
        address_type : str, optional
            The type of address to create (default is P2PKH)
            
        Returns
        -------
        UnifiedAddress
            A new UnifiedAddress object
            
        Raises
        ------
        ValueError
            If the address type is not supported for hash160
        """
        if address_type == P2PKH_ADDRESS:
            address = P2pkhAddress(hash160=hash_str)
        elif address_type == P2SH_ADDRESS:
            address = P2shAddress(hash160=hash_str)
        else:
            raise ValueError(f"Cannot create {address_type} directly from hash160")
        
        return cls(address)
    
    @classmethod
    def from_witness_program(cls, witness_program: str, address_type: AddressType = P2WPKH_ADDRESS_V0) -> 'UnifiedAddress':
        """Create a UnifiedAddress from a witness program.
        
        Parameters
        ----------
        witness_program : str
            The witness program hex string
        address_type : str, optional
            The type of address to create (default is P2WPKH)
            
        Returns
        -------
        UnifiedAddress
            A new UnifiedAddress object
            
        Raises
        ------
        ValueError
            If the address type is not supported for witness program
        """
        if address_type == P2WPKH_ADDRESS_V0:
            address = P2wpkhAddress(witness_program=witness_program)
        elif address_type == P2WSH_ADDRESS_V0:
            address = P2wshAddress(witness_program=witness_program)
        elif address_type == P2TR_ADDRESS_V1:
            address = P2trAddress(witness_program=witness_program)
        else:
            raise ValueError(f"Cannot create {address_type} from witness program")
        
        return cls(address)
    
    @staticmethod
    def _detect_address_type(address_str: str) -> AddressType:
        """Detect the address type from an address string.
        
        Parameters
        ----------
        address_str : str
            The address string
            
        Returns
        -------
        str
            The detected address type
            
        Raises
        ------
        ValueError
            If the address type cannot be detected
        """
        # Try each address type until one works
        try:
            # Try P2PKH
            P2pkhAddress(address=address_str)
            return P2PKH_ADDRESS
        except ValueError:
            pass
        
        try:
            # Try P2SH
            P2shAddress(address=address_str)
            return P2SH_ADDRESS
        except ValueError:
            pass
        
        try:
            # Try P2WPKH
            P2wpkhAddress(address=address_str)
            return P2WPKH_ADDRESS_V0
        except (ValueError, TypeError):
            pass
        
        try:
            # Try P2WSH
            P2wshAddress(address=address_str)
            return P2WSH_ADDRESS_V0
        except (ValueError, TypeError):
            pass
        
        try:
            # Try P2TR
            P2trAddress(address=address_str)
            return P2TR_ADDRESS_V1
        except (ValueError, TypeError):
            pass
        
        raise ValueError(f"Could not detect address type for {address_str}")
    
    def to_script_pub_key(self) -> Script:
        """Get the scriptPubKey for this address.
        
        Returns
        -------
        Script
            The scriptPubKey for this address
        """
        return self.address.to_script_pub_key()
    
    def to_address_type(self, address_type: AddressType) -> 'UnifiedAddress':
        """Convert the address to a different type if possible.
        
        Parameters
        ----------
        address_type : str
            The target address type
            
        Returns
        -------
        UnifiedAddress
            A new UnifiedAddress object of the requested type
            
        Raises
        ------
        ValueError
            If conversion to the requested type is not possible
        """
        # If already the requested type, return self
        if self.address_type == address_type:
            return self
        
        # P2PKH -> P2WPKH, P2SH-P2WPKH conversions
        if self.address_type == P2PKH_ADDRESS:
            # Extract the hash160
            hash160 = self.address.to_hash160()
            
            if address_type == P2WPKH_ADDRESS_V0:
                # P2PKH -> P2WPKH
                address = P2wpkhAddress(witness_program=hash160)
                return UnifiedAddress(address)
            
            elif address_type == P2SH_ADDRESS:
                # P2PKH -> P2SH-P2WPKH (nested SegWit)
                # Create P2WPKH scriptPubKey
                p2wpkh_script = Script(['OP_0', hash160])
                # Create P2SH address from that script
                address = P2shAddress(script=p2wpkh_script)
                return UnifiedAddress(address)
        
        # P2SH -> P2WSH (only if it's a nested SegWit)
        # This is a limited case and generally requires knowing the redeem script
        
        # P2WPKH -> P2PKH, P2SH-P2WPKH
        if self.address_type == P2WPKH_ADDRESS_V0:
            # Extract the witness program
            witness_program = self.address.to_witness_program()
            
            if address_type == P2PKH_ADDRESS:
                # P2WPKH -> P2PKH
                address = P2pkhAddress(hash160=witness_program)
                return UnifiedAddress(address)
            
            elif address_type == P2SH_ADDRESS:
                # P2WPKH -> P2SH-P2WPKH (nested SegWit)
                p2wpkh_script = Script(['OP_0', witness_program])
                address = P2shAddress(script=p2wpkh_script)
                return UnifiedAddress(address)
        
        # P2WSH -> P2SH-P2WSH
        if self.address_type == P2WSH_ADDRESS_V0 and address_type == P2SH_ADDRESS:
            witness_program = self.address.to_witness_program()
            p2wsh_script = Script(['OP_0', witness_program])
            address = P2shAddress(script=p2wsh_script)
            return UnifiedAddress(address)
        
        # No other direct conversions are possible without additional data
        raise ValueError(f"Cannot convert from {self.address_type} to {address_type}")
    
    def to_string(self) -> str:
        """Get the address as a string.
        
        Returns
        -------
        str
            The address string
        """
        return self.address.to_string()
    
    def __str__(self) -> str:
        return self.to_string()
    
    def __repr__(self) -> str:
        return f"UnifiedAddress('{self.to_string()}', '{self.address_type}')"
    
    def __eq__(self, other: Any) -> bool:
        if isinstance(other, UnifiedAddress):
            return self.to_string() == other.to_string()
        elif isinstance(other, str):
            return self.to_string() == other
        return False