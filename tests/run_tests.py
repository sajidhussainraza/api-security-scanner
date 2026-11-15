#!/usr/bin/env python3
"""Run the api-security-scanner test suite.

Usage:
    python3 tests/run_tests.py
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
