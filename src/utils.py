"""Utility functions, warning suppression, and stderr containment."""

import os
import sys
import warnings
import logging
from contextlib import contextmanager

# Suppress third-party library warnings so they never reach the terminal.
warnings.filterwarnings("ignore")
logging.getLogger().setLevel(logging.ERROR)
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "3")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")


@contextmanager
def silence_stderr():
    """Redirect stderr to devnull to suppress external library chatter."""
    old_stderr = sys.stderr
    try:
        sys.stderr = open(os.devnull, "w")
        yield
    finally:
        sys.stderr.close()
        sys.stderr = old_stderr


def intercept_warnings(func):
    """Decorator that wraps a function with stderr suppression."""
    def wrapper(*args, **kwargs):
        with silence_stderr():
            return func(*args, **kwargs)
    return wrapper
