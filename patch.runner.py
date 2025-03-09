#!/usr/bin/env python
"""
This is a simple script to run the bitcoin-utils tests with patches applied.
"""

import os
import sys
import unittest
import subprocess

# Flag to track if we've already patched
_patching_applied = False

def apply_all_patches():
    """Apply all patches to unittest and builtins"""
    global _patching_applied
    
    if _patching_applied:
        print("Patches already applied, skipping...")
        return
    
    # Apply the direct patch
    from direct_patch import apply_patches
    apply_patches()
    
    # Try to import the original modules too, just in case
    try:
        # Import other helpers if they exist
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        
        # Try fix_tests if it exists
        try:
            import fix_tests
            print("Imported fix_tests.py")
        except ImportError:
            pass
            
    except Exception as e:
        print(f"Warning: {e}")
    
    _patching_applied = True
    print("All patches applied successfully")

if __name__ == "__main__":
    # Apply patches
    apply_all_patches()
    
    # Run the tests
    print("\nRunning tests with patches applied...\n")
    subprocess.call([sys.executable, "-m", "unittest", "discover", "tests"])