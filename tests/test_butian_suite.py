"""Expose the Butian test suite to ``python -m unittest discover -s tests``."""

import os


def load_tests(loader, standard_tests, pattern):
    suite_dir = os.path.join(os.path.dirname(__file__), "butian")
    return loader.discover(
        suite_dir,
        pattern=pattern or "test*.py",
        top_level_dir=suite_dir,
    )
