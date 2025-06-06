
#!/usr/bin/env python3
"""
Test runner script for user API tests.
Run this script to execute all pytest tests.
"""

import subprocess
import sys


def run_tests():
    """Run pytest tests with verbose output."""
    try:
        # Run pytest with verbose output and coverage if available
        result = subprocess.run([
            sys.executable, '-m', 'pytest', 
            'test_users.py', 
            '-v', 
            '--tb=short'
        ], capture_output=False)
        
        return result.returncode
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
