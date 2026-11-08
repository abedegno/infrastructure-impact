"""Flushed, metadata-only phase timings for the collection/publication pipeline."""

import json
import sys
from contextlib import contextmanager
from time import perf_counter, process_time

try:
    import resource
except ImportError:  # Not available on every supported Python platform.
    resource = None


FAILURE_CODES = frozenset(
    {
        "stream_deadline",
        "byte_budget",
        "query_mismatch",
        "schema",
        "memory",
        "recursion",
        "unclassified",
    }
)


def _failure_code(error):
    """Classify known failures without formatting arbitrary exception details."""
    if isinstance(error, MemoryError):
        return "memory"
    if isinstance(error, RecursionError):
        return "recursion"
    if (
        type(error).__module__ == "jsonschema.exceptions"
        and type(error).__name__ == "ValidationError"
    ):
        return "schema"
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        return {
            "stream deadline": "stream_deadline",
            "decoded byte budget": "byte_budget",
            "claim byte budget": "byte_budget",
            "cross-claim linkage byte budget": "byte_budget",
            "selected byte budget": "byte_budget",
            "native switching query mismatch": "query_mismatch",
        }.get(error.args[0], "unclassified")
    return "unclassified"


@contextmanager
def phase(label):
    """Use static labels and failure codes, never payloads or exception details."""
    started = perf_counter()
    try:
        cpu_started = process_time()
    except (NotImplementedError, OSError, ValueError):
        cpu_started = None

    def emit(state, failure=None):
        metrics = {} if failure is None else {"failure_code": failure}
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
    except BaseException as error:
        emit("failed", _failure_code(error))
        raise
    else:
        emit("completed")
