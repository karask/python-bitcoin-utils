from typing import Optional, Tuple, Union, List, Any, Callable, overload

# We'll only define the parts of sympy that are used in the bitcoin-utils code
# This is a minimal stub file for the specific functionality used

class ntheory:
    @staticmethod
    def sqrt_mod(a: int, p: int, all_roots: bool = False) -> Optional[Union[int, Tuple[int, int]]]: ...