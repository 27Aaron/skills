"""Shared pytest configuration for butian tests."""

import os
import sys

# Ensure butian scripts are importable from both pytest root and individual test files.
_butian_scripts = os.path.join(os.path.dirname(__file__), "butian", "scripts")
if _butian_scripts not in sys.path:
    sys.path.insert(0, _butian_scripts)
