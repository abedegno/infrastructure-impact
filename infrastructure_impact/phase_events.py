"""Flushed, metadata-only phase timings for the collection/publication pipeline."""

import json
import sys
from contextlib import contextmanager
from time import perf_counter


@contextmanager
def phase(label):
    """Use static call-site labels only; never log arguments, payloads or errors."""
    started = perf_counter()

    def emit(state):
        print(
            json.dumps(
                {
                    "event": "phase",
                    "phase": label,
                    "state": state,
                    "elapsed_seconds": round(perf_counter() - started, 6),
                },
                separators=(",", ":"),
            ),
            file=sys.stderr,
            flush=True,
        )

    emit("started")
    try:
        yield
    except BaseException:
        emit("failed")
        raise
    else:
        emit("completed")
