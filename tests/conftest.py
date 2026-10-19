from __future__ import annotations

import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def short_dir() -> Iterator[Path]:
    """A data directory with a short path: macOS caps Unix socket paths at 104 bytes."""
    d = Path(tempfile.mkdtemp(prefix="rh-", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)
