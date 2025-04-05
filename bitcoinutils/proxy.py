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

from __future__ import annotations
from typing import Optional, Any, Dict, List, Union, Tuple, Callable, TypeVar, cast, overload

# For type checking, we need to handle the imported library
from bitcoinrpc.authproxy import AuthServiceProxy

from bitcoinutils.setup import get_network
from bitcoinutils.constants import NETWORK_DEFAULT_PORTS


T = TypeVar('T')
JSONDict = Dict[str, Any]
JSONList = List[Any]
JSONValue = Union[str, int, float, bool, None, JSONDict, JSONList]


class RPCError(Exception):
    """Exception raised for errors when interfacing with the Bitcoin node.

    Attributes:
        message -- explanation of the error
        code -- error code returned by the node
    """

    def __init__(self, message: str, code: Optional[int] = None):
        self.message = message
        self.code = code
        super().__init__(f"RPC Error ({code}): {message}" if code else message)


class NodeProxy:
    """Bitcoin node proxy that can call all of Bitcoin's JSON-RPC functionality.

    This class provides a convenient interface to interact with a Bitcoin node using
    the JSON-RPC protocol. It supports all methods available in Bitcoin Core and
    handles authentication, connection management, and error handling.

    Attributes
    ----------
    proxy : object
        an instance of bitcoinrpc.authproxy.AuthServiceProxy
    
    Methods
    -------
    call(method, *params)
        Calls any RPC method with provided parameters
    get_blockchain_info()
        Returns information about the blockchain
    get_network_info()
        Returns information about the network
    get_wallet_info()
        Returns information about the wallet
    get_new_address(label="", address_type=None)
        Generates a new address
    ... (other methods)
    """

    def __init__(
        self,
        rpcuser: str,
        rpcpassword: str,
        host: Optional[str] = None,
        port: Optional[int] = None,
        timeout: int = 30,
        use_https: bool = False,
    ) -> None:
        """Connects to a Bitcoin node using provided credentials.

        Parameters
        ----------
        rpcuser : str
            RPC username as defined in bitcoin.conf
        rpcpassword : str
            RPC password as defined in bitcoin.conf
        host : str, optional
            Host where the Bitcoin node resides; defaults to 127.0.0.1
        port : int, optional
            Port to connect to; uses default ports according to network
        timeout : int, optional
            Timeout for RPC calls in seconds; defaults to 30
        use_https : bool, optional
            Whether to use HTTPS for the connection; defaults to False

        Raises
        ------
        ValueError
            If rpcuser and/or rpcpassword are not specified
        """
        if not rpcuser or not rpcpassword:
            raise ValueError("rpcuser or rpcpassword is missing")

        if not host:
            host = "127.0.0.1"
        if not port:
            port = NETWORK_DEFAULT_PORTS[get_network()]

        protocol = "https" if use_https else "http"
        service_url = f"{protocol}://{rpcuser}:{rpcpassword}@{host}:{port}"
        
        self.proxy = AuthServiceProxy(service_url, timeout=timeout)

    def __call__(self, method: str, *params: Any) -> Any:
        """Directly call any Bitcoin Core RPC method.
        
        This is a convenience method that allows calling RPC methods directly 
        through the NodeProxy instance.
        
        Parameters
        ----------
        method : str
            The RPC method name
        *params : Any
            Parameters to pass to the RPC method
            
        Returns
        -------
        Any
            The result of the RPC call
            
        Raises
        ------
        RPCError
            If the RPC call fails
        """
        return self.call(method, *params)

    def call(self, method: str, *params: Any) -> Any:
        """Call any Bitcoin Core RPC method.
        
        Parameters
        ----------
        method : str
            The RPC method name
        *params : Any
            Parameters to pass to the RPC method
            
        Returns
        -------
        Any
            The result of the RPC call
            
        Raises
        ------
        RPCError
            If the RPC call fails
        """
        try:
            rpc_method = getattr(self.proxy, method)
            return rpc_method(*params)
        except Exception as e:
            # Extract error code if available
            error_code = None
            if hasattr(e, 'error') and 'code' in e.error:
                error_code = e.error['code']
            
            raise RPCError(str(e), error_code)

    # Convenience methods for common RPC calls
    # Blockchain methods
    def get_blockchain_info(self) -> JSONDict:
        """Get information about the blockchain.
        
        Returns
        -------
        dict
            Information about the blockchain including the current 
            blockchain height, difficulty, chain (main/test/regtest), etc.
        """
        result = self.call('getblockchaininfo')
        return cast(JSONDict, result)
    
    def get_block_count(self) -> int:
        """Get the current block height of the blockchain.
        
        Returns
        -------
        int
            The current block height
        """
        result = self.call('getblockcount')
        return cast(int, result)
    
    def get_block_hash(self, height: int) -> str:
        """Get the block hash for a specific height.
        
        Parameters
        ----------
        height : int
            The block height
            
        Returns
        -------
        str
            The block hash
        """
        result = self.call('getblockhash', height)
        return cast(str, result)
    
    def get_block(self, block_hash: str, verbosity: int = 1) -> Union[str, JSONDict]:
        """Get block data for a specific block hash.
        
        Parameters
        ----------
        block_hash : str
            The block hash
        verbosity : int, optional
            0 for hex-encoded data, 1 for a JSON object, 2 for JSON object with transaction data
            
        Returns
        -------
        Union[str, dict]
            Block data as hex string (verbosity=0) or JSON object (verbosity>0)
        """
        result = self.call('getblock', block_hash, verbosity)
        if verbosity == 0:
            return cast(str, result)
        return cast(JSONDict, result)
    
    def get_difficulty(self) -> float:
        """Get the current network difficulty.
        
        Returns
        -------
        float
            The current difficulty
        """
        result = self.call('getdifficulty')
        return cast(float, result)
    
    def get_chain_tips(self) -> List[JSONDict]:
        """Get information about chain tips.
        
        Returns
        -------
        List[dict]
            List of chain tips
        """
        result = self.call('getchaintips')
        return cast(List[JSONDict], result)

    # Wallet methods
    def get_balance(self, dummy: str = "*", minconf: int = 0, include_watchonly: bool = False) -> float:
        """Get the total balance of the wallet.
        
        Parameters
        ----------
        dummy : str, optional
            Remains for backward compatibility (must be "*" for selection of all wallets)
        minconf : int, optional
            Minimum number of confirmations
        include_watchonly : bool, optional
            Whether to include watch-only addresses
            
        Returns
        -------
        float
            The wallet balance in BTC
        """
        result = self.call('getbalance', dummy, minconf, include_watchonly)
        return cast(float, result)
    
    def get_wallet_info(self) -> JSONDict:
        """Get information about the wallet.
        
        Returns
        -------
        dict
            Information about the wallet
        """
        result = self.call('getwalletinfo')
        return cast(JSONDict, result)
    
    def get_new_address(self, label: str = "", address_type: Optional[str] = None) -> str:
        """Generate a new address.
        
        Parameters
        ----------
        label : str, optional
            A label for the address
        address_type : str, optional
            The address type (legacy, p2sh-segwit, bech32, or null for default)
            
        Returns
        -------
        str
            The new address
        """
        if address_type:
            result = self.call('getnewaddress', label, address_type)
        else:
            result = self.call('getnewaddress', label)
        return cast(str, result)
    
    def get_raw_change_address(self, address_type: Optional[str] = None) -> str:
        """Generate a new address for receiving change.
        
        Parameters
        ----------
        address_type : str, optional
            The address type (legacy, p2sh-segwit, bech32, or null for default)
            
        Returns
        -------
        str
            The new change address
        """
        if address_type:
            result = self.call('getrawchangeaddress', address_type)
        else:
            result = self.call('getrawchangeaddress')
        return cast(str, result)
    
    def list_unspent(
        self, 
        minconf: int = 1, 
        maxconf: int = 9999999, 
        addresses: Optional[List[str]] = None,
        include_unsafe: bool = True,
        query_options: Optional[JSONDict] = None
    ) -> List[JSONDict]:
        """Get a list of unspent transaction outputs.
        
        Parameters
        ----------
        minconf : int, optional
            Minimum number of confirmations
        maxconf : int, optional
            Maximum number of confirmations
        addresses : List[str], optional
            Filter by addresses
        include_unsafe : bool, optional
            Include outputs that are not safe to spend
        query_options : dict, optional
            Additional query options
            
        Returns
        -------
        List[dict]
            List of unspent transaction outputs
        """
        if addresses is None:
            addresses = []
            
        if query_options:
            result = self.call('listunspent', minconf, maxconf, addresses, include_unsafe, query_options)
        else:
            result = self.call('listunspent', minconf, maxconf, addresses, include_unsafe)
        return cast(List[JSONDict], result)
    
    def list_transactions(
        self, 
        label: str = "*", 
        count: int = 10, 
        skip: int = 0, 
        include_watchonly: bool = False
    ) -> List[JSONDict]:
        """Get a list of wallet transactions.
        
        Parameters
        ----------
        label : str, optional
            Label to filter transactions
        count : int, optional
            Number of transactions to return
        skip : int, optional
            Number of transactions to skip
        include_watchonly : bool, optional
            Whether to include watch-only addresses
            
        Returns
        -------
        List[dict]
            List of wallet transactions
        """
        result = self.call('listtransactions', label, count, skip, include_watchonly)
        return cast(List[JSONDict], result)
    
    def get_transaction(self, txid: str, include_watchonly: bool = False) -> JSONDict:
        """Get detailed information about a transaction.
        
        Parameters
        ----------
        txid : str
            The transaction ID
        include_watchonly : bool, optional
            Whether to include watch-only addresses
            
        Returns
        -------
        dict
            Detailed information about the transaction
        """
        result = self.call('gettransaction', txid, include_watchonly)
        return cast(JSONDict, result)

    # Network methods
    def get_network_info(self) -> JSONDict:
        """Get information about the network.
        
        Returns
        -------
        dict
            Information about the network
        """
        result = self.call('getnetworkinfo')
        return cast(JSONDict, result)
    
    def get_peer_info(self) -> List[JSONDict]:
        """Get information about connected peers.
        
        Returns
        -------
        List[dict]
            List of connected peers
        """
        result = self.call('getpeerinfo')
        return cast(List[JSONDict], result)
    
    def get_node_addresses(self, count: int = 1) -> List[JSONDict]:
        """Get known addresses for network nodes.
        
        Parameters
        ----------
        count : int, optional
            The number of addresses to return
            
        Returns
        -------
        List[dict]
            List of node addresses
        """
        result = self.call('getnodeaddresses', count)
        return cast(List[JSONDict], result)
    
    def get_net_totals(self) -> JSONDict:
        """Get network traffic statistics.
        
        Returns
        -------
        dict
            Network traffic statistics
        """
        result = self.call('getnettotals')
        return cast(JSONDict, result)

    # Transaction methods
    def create_raw_transaction(
        self, 
        inputs: List[JSONDict], 
        outputs: Union[JSONDict, List[JSONDict]], 
        locktime: int = 0, 
        replaceable: bool = False
    ) -> str:
        """Create a raw transaction without signing it.
        
        Parameters
        ----------
        inputs : List[dict]
            List of transaction inputs
        outputs : Union[dict, List[dict]]
            Dictionary with addresses as keys and amounts as values, or a list of outputs
        locktime : int, optional
            Transaction locktime
        replaceable : bool, optional
            Whether the transaction is replaceable (BIP125)
            
        Returns
        -------
        str
            The hex-encoded raw transaction
        """
        result = self.call('createrawtransaction', inputs, outputs, locktime, replaceable)
        return cast(str, result)
    
    def sign_raw_transaction_with_wallet(
        self, 
        hex_string: str, 
        prev_txs: Optional[List[JSONDict]] = None, 
        sighash_type: str = "ALL"
    ) -> JSONDict:
        """Sign a raw transaction with the keys in the wallet.
        
        Parameters
        ----------
        hex_string : str
            The hex-encoded raw transaction
        prev_txs : List[dict], optional
            Previous transactions being spent
        sighash_type : str, optional
            Signature hash type
            
        Returns
        -------
        dict
            The signed transaction
        """
        if prev_txs:
            result = self.call('signrawtransactionwithwallet', hex_string, prev_txs, sighash_type)
        else:
            result = self.call('signrawtransactionwithwallet', hex_string)
        return cast(JSONDict, result)
    
    def send_raw_transaction(self, hex_string: str, max_fee_rate: Optional[float] = None) -> str:
        """Submit a raw transaction to the network.
        
        Parameters
        ----------
        hex_string : str
            The hex-encoded raw transaction
        max_fee_rate : float, optional
            Reject transactions with a fee rate higher than this (in BTC/kB)
            
        Returns
        -------
        str
            The transaction hash
        """
        if max_fee_rate is not None:
            result = self.call('sendrawtransaction', hex_string, max_fee_rate)
        else:
            result = self.call('sendrawtransaction', hex_string)
        return cast(str, result)
    
    def decode_raw_transaction(self, hex_string: str, is_witness: bool = True) -> JSONDict:
        """Decode a raw transaction.
        
        Parameters
        ----------
        hex_string : str
            The hex-encoded raw transaction
        is_witness : bool, optional
            Whether the transaction is in witness format
            
        Returns
        -------
        dict
            The decoded transaction
        """
        result = self.call('decoderawtransaction', hex_string, is_witness)
        return cast(JSONDict, result)
    
    def get_raw_transaction(self, txid: str, verbose: bool = False, blockhash: Optional[str] = None) -> Union[str, JSONDict]:
        """Get a raw transaction.
        
        Parameters
        ----------
        txid : str
            The transaction ID
        verbose : bool, optional
            Whether to return detailed information
        blockhash : str, optional
            The block hash in which to look for the transaction
            
        Returns
        -------
        Union[str, dict]
            The raw transaction as hex string or a JSON object if verbose=True
        """
        if blockhash:
            result = self.call('getrawtransaction', txid, verbose, blockhash)
        else:
            result = self.call('getrawtransaction', txid, verbose)
        if verbose:
            return cast(JSONDict, result)
        return cast(str, result)
    
    def estimate_smart_fee(self, conf_target: int, estimate_mode: str = "CONSERVATIVE") -> JSONDict:
        """Estimate the fee for a transaction.
        
        Parameters
        ----------
        conf_target : int
            Confirmation target in blocks
        estimate_mode : str, optional
            Fee estimate mode (UNSET, ECONOMICAL, CONSERVATIVE)
            
        Returns
        -------
        dict
            Estimated fee information
        """
        result = self.call('estimatesmartfee', conf_target, estimate_mode)
        return cast(JSONDict, result)

    # Utility methods
    def validate_address(self, address: str) -> JSONDict:
        """Validate a Bitcoin address.
        
        Parameters
        ----------
        address : str
            The address to validate
            
        Returns
        -------
        dict
            Information about the address
        """
        result = self.call('validateaddress', address)
        return cast(JSONDict, result)
    
    def get_mempool_info(self) -> JSONDict:
        """Get information about the memory pool.
        
        Returns
        -------
        dict
            Information about the memory pool
        """
        result = self.call('getmempoolinfo')
        return cast(JSONDict, result)
    
    def get_mempool_entry(self, txid: str) -> JSONDict:
        """Get mempool data for a transaction.
        
        Parameters
        ----------
        txid : str
            The transaction ID
            
        Returns
        -------
        dict
            The mempool entry
        """
        result = self.call('getmempoolentry', txid)
        return cast(JSONDict, result)
    
    def get_mempool_ancestors(self, txid: str, verbose: bool = False) -> Union[List[str], JSONDict]:
        """Get mempool ancestors for a transaction.
        
        Parameters
        ----------
        txid : str
            The transaction ID
        verbose : bool, optional
            Whether to return detailed information
            
        Returns
        -------
        Union[List[str], dict]
            List of ancestor transaction IDs or detailed information
        """
        result = self.call('getmempoolancestors', txid, verbose)
        if verbose:
            return cast(JSONDict, result)
        return cast(List[str], result)
    
    def get_mempool_descendants(self, txid: str, verbose: bool = False) -> Union[List[str], JSONDict]:
        """Get mempool descendants for a transaction.
        
        Parameters
        ----------
        txid : str
            The transaction ID
        verbose : bool, optional
            Whether to return detailed information
            
        Returns
        -------
        Union[List[str], dict]
            List of descendant transaction IDs or detailed information
        """
        result = self.call('getmempooldescendants', txid, verbose)
        if verbose:
            return cast(JSONDict, result)
        return cast(List[str], result)

    # Mining methods
    def get_mining_info(self) -> JSONDict:
        """Get mining information.
        
        Returns
        -------
        dict
            Mining information
        """
        result = self.call('getmininginfo')
        return cast(JSONDict, result)
    
    def get_block_template(self, template_request: Optional[JSONDict] = None) -> JSONDict:
        """Get block template for miners.
        
        Parameters
        ----------
        template_request : dict, optional
            Template request parameters
            
        Returns
        -------
        dict
            Block template information
        """
        if template_request:
            result = self.call('getblocktemplate', template_request)
        else:
            result = self.call('getblocktemplate')
        return cast(JSONDict, result)
    
    def generate_to_address(self, nblocks: int, address: str, max_tries: int = 1000000) -> List[str]:
        """Generate blocks to a specific address.
        
        Parameters
        ----------
        nblocks : int
            Number of blocks to generate
        address : str
            The address to send the newly generated bitcoin to
        max_tries : int, optional
            Maximum number of tries
            
        Returns
        -------
        List[str]
            List of block hashes
        """
        result = self.call('generatetoaddress', nblocks, address, max_tries)
        return cast(List[str], result)

    # Wallet management methods
    def create_wallet(
        self, 
        wallet_name: str, 
        disable_private_keys: bool = False, 
        blank: bool = False, 
        passphrase: str = "", 
        avoid_reuse: bool = False,
        descriptors: Optional[bool] = None,
        load_on_startup: bool = False
    ) -> JSONDict:
        """Create a new wallet.
        
        Parameters
        ----------
        wallet_name : str
            The name of the new wallet
        disable_private_keys : bool, optional
            Whether to disable private keys
        blank : bool, optional
            Whether to create a blank wallet
        passphrase : str, optional
            The wallet passphrase
        avoid_reuse : bool, optional
            Whether to avoid address reuse
        descriptors : bool, optional
            Whether to create a descriptor wallet
        load_on_startup : bool, optional
            Whether to load the wallet on startup
            
        Returns
        -------
        dict
            Information about the created wallet
        """
        args = [wallet_name, disable_private_keys, blank, passphrase, avoid_reuse]
        
        # Handle optional parameters for newer Bitcoin Core versions
        if descriptors is not None:
            args.append(descriptors)
            if load_on_startup is not None:
                args.append(load_on_startup)
        
        result = self.call('createwallet', *args)
        return cast(JSONDict, result)
    
    def list_wallets(self) -> List[str]:
        """List available wallets.
        
        Returns
        -------
        List[str]
            List of wallet names
        """
        result = self.call('listwallets')
        return cast(List[str], result)
    
    def load_wallet(self, filename: str, load_on_startup: Optional[bool] = None) -> JSONDict:
        """Load a wallet.
        
        Parameters
        ----------
        filename : str
            The wallet filename
        load_on_startup : bool, optional
            Whether to load the wallet on startup
            
        Returns
        -------
        dict
            Information about the loaded wallet
        """
        if load_on_startup is not None:
            result = self.call('loadwallet', filename, load_on_startup)
        else:
            result = self.call('loadwallet', filename)
        return cast(JSONDict, result)
    
    def unload_wallet(self, wallet_name: str = "") -> JSONDict:
        """Unload a wallet.
        
        Parameters
        ----------
        wallet_name : str, optional
            The wallet name to unload
            
        Returns
        -------
        dict
            Result of the unload operation
        """
        if wallet_name:
            result = self.call('unloadwallet', wallet_name)
        else:
            result = self.call('unloadwallet')
        return cast(JSONDict, result)

    # For backwards compatibility
    def get_proxy(self) -> Any:
        """Returns the AuthServiceProxy object.
        
        This method is maintained for backwards compatibility.
        
        Returns
        -------
        AuthServiceProxy
            The AuthServiceProxy object
        """
        return self.proxy