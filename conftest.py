"""
Pytest configuration file that applies all fixes before tests run.
This avoids having to modify each test file individually.
"""

import sys
import os

# Add the parent directory to path to ensure imports work
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

# Import and apply fixes
def pytest_configure(config):
    """Apply fixes before tests run."""
    print("Configuring Bitcoin test environment...")
    try:
        # Import and apply the final fix solution
        import fix_final
        print("Successfully applied Bitcoin utils fixes")
    except ImportError as e:
        print(f"Error importing fix_final: {e}")
        print("Trying alternative fixes...")
        
        try:
            # Try to import and apply individual fixes
            import fix_all
            import fix_all_issues
            print("Successfully applied individual fixes")
        except ImportError:
            print("Warning: Could not apply all fixes. Tests may fail.")