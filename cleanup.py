"""
Cleanup script to remove conflicting module files and ensure proper test environment.
"""

import os
import sys
import shutil

# Get the root directory and tests directory
root_dir = os.path.dirname(os.path.abspath(__file__))
tests_dir = os.path.join(root_dir, 'tests')

# Files that should only exist in tests directory
test_only_files = [
    'test_keys_patch.py',
    'address_fix.py',
    'transaction_fix.py'
]

# Check and remove conflicting files from root directory
for filename in test_only_files:
    root_file = os.path.join(root_dir, filename)
    tests_file = os.path.join(tests_dir, filename)
    
    # If file exists in root and should be in tests, delete it from root
    if os.path.exists(root_file) and os.path.isfile(root_file):
        print(f"Removing conflicting file: {root_file}")
        os.remove(root_file)
    
    # Ensure the file exists in tests directory
    if not os.path.exists(tests_file):
        dummy_content = f'"""\nDummy module for {filename}\n"""\n'
        print(f"Creating {filename} in tests directory")
        with open(tests_file, 'w') as f:
            f.write(dummy_content)

print("Cleanup complete. Run your tests now.")