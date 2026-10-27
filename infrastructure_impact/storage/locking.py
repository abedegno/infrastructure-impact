"""Shared process exclusion for collection and explicit normalization writers."""

import fcntl
from contextlib import contextmanager

from ..settings import Paths


@contextmanager
def writer_lock():
    path = Paths.from_env().home / "data/collector.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
