from typing import Any, Callable, Dict, List, Optional, Union, overload

class JSONRPCException(Exception):
    error: Dict[str, Any]
    
    def __init__(self, rpc_error: Dict[str, Any]) -> None: ...


class AuthServiceProxy:
    def __init__(self, service_url: str, service_name: Optional[str] = None, timeout: int = 30, 
                 connection: Optional[Any] = None) -> None: ...
    
    def __getattr__(self, name: str) -> 'AuthServiceProxy': ...
    
    def __call__(self, *args: Any) -> Any: ...