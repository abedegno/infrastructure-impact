"""One stat-checked streaming copy of an already checkpointed SQLite input."""

import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


@contextmanager
def stable_checkpoint(database: Path, *, error_prefix: str, changed_error=ValueError):
    """Yield a disposable copy path, without opening or checkpointing source SQLite.

    Nonempty WAL/journal files and ordinary concurrent source changes fail closed.
    Callers select their existing public error namespace and baseline exception.
    This detects ordinary writers; it does not authenticate a hostile filesystem.
    """
    supplied = Path(database)
    source = supplied.resolve(strict=True)
    if not source.is_file():
        raise ValueError(error_prefix + "_input_missing")

    def identity(path):
        try:
            st = path.stat()
        except FileNotFoundError:
            return None
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def descriptor_identity(st):
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)

    def state():
        return (
            identity(source),
            identity(Path(str(source) + "-wal")),
            identity(Path(str(source) + "-journal")),
        )

    before = state()
    if before[0] is None:
        raise ValueError(error_prefix + "_input_missing")
    if any(journal is not None and journal[2] for journal in before[1:]):
        raise ValueError(error_prefix + "_checkpoint_required")
    with TemporaryDirectory(
        prefix="impact-" + error_prefix.replace("_", "-") + "-preview-"
    ) as directory:
        copy = Path(directory) / "checkpoint.sqlite"
        with source.open("rb") as incoming, copy.open("xb") as outgoing:
            if descriptor_identity(os.fstat(incoming.fileno())) != before[0]:
                raise changed_error(error_prefix + "_baseline_changed")
            shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
            after_read = os.fstat(incoming.fileno())
        if (
            state() != before
            or supplied.resolve(strict=True) != source
            or descriptor_identity(after_read) != before[0]
        ):
            raise changed_error(error_prefix + "_baseline_changed")
        yield copy
