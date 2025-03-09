# test_helper_patch.py
"""
This file is designed to be imported by test_helper.py at the top.
"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the monkey patch to apply all fixes
try:
    import monkey_patch
except ImportError:
    print("WARNING: Could not import monkey_patch.py")