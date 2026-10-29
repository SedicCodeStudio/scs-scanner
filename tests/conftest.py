"""Test setup: every test run uses its own empty home folder, so nothing touches the real ~/.scs-scanner."""
import atexit
import os
import shutil
import sys
import tempfile

_HOME = tempfile.mkdtemp(prefix="scs-test-home-")
atexit.register(shutil.rmtree, _HOME, ignore_errors=True)
os.environ["HOME"] = _HOME
os.environ["USERPROFILE"] = _HOME
os.environ["SCS_HOME"] = _HOME
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from scs.core import Context  # noqa: E402


@pytest.fixture
def ctx():
    return Context(log=lambda msg: None)


@pytest.fixture
def home():
    return _HOME
