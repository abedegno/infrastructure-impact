"""Flushed, metadata-only phase timings for the collection/publication pipeline."""

import json
import sys
from contextlib import contextmanager
from time import perf_counter, process_time

try:
    import resource
except ImportError:  # Not available on every supported Python platform.
    resource = None


@contextmanager
def phase(label):
    """Use static call-site labels only; never log arguments, payloads or errors."""
    started = perf_counter()
    try:
        cpu_started = process_time()
    except (NotImplementedError, OSError, ValueError):
        cpu_started = None

    def emit(state):
        metrics = {}
        try:
            cpu = process_time() - cpu_started
            if type(cpu) in (int, float) and 0 <= cpu <= 86_400:
                metrics["process_cpu_seconds"] = round(cpu, 6)
        except (NotImplementedError, OSError, TypeError, ValueError):
            pass
        try:
            # SELF is this emitting process; peak RSS spans its lifetime, not the phase.
            rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform in ("darwin", "linux") and type(rss) is int and 0 <= rss <= 2**50:
                peak = rss if sys.platform == "darwin" else rss * 1024
                if peak <= 2**50:
                    metrics["peak_resident_bytes"] = peak
        except (AttributeError, NotImplementedError, OSError, ValueError):
            pass
        print(
            json.dumps(
                {
                    "event": "phase",
                    "phase": label,
                    "state": state,
                    "elapsed_seconds": round(perf_counter() - started, 6),
                    **metrics,
                },
                allow_nan=False,
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
