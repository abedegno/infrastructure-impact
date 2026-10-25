"""Single writer process with a timezone-aware daily schedule."""

import fcntl
import json
import logging
import os
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .application.benchmark import run as benchmark
from .application.jobs import execute
from .application.publication import build
from .application.reporting import report
from .collection.config import load_config
from .collection.service import run
from .settings import Paths

LOG = logging.getLogger(__name__)


def next_daily(current, hour=8, minute=15, zone="Europe/London"):
    local = current.astimezone(ZoneInfo(zone))
    candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= local:
        tomorrow = local.date() + timedelta(days=1)
        candidate = datetime.combine(tomorrow, candidate.timetz(), tzinfo=ZoneInfo(zone))
    return candidate.astimezone(timezone.utc)


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


def collect_once():
    paths = Paths.from_env()
    for directory in ("benchmark", "data", "ops"):
        (paths.home / directory).mkdir(parents=True, exist_ok=True)
    with writer_lock() as acquired:
        if not acquired:
            LOG.info("Another writer holds the collection lock; skipping overlap")
            return {"outcome": "skipped"}
        result = execute(
            lambda: run(load_config(), limit=4), benchmark, report, build, status_fn=write_status
        )
        LOG.info("Collection result %s", json.dumps(result))
        return result


def write_status(status):
    root = Paths.from_env().publications
    root.mkdir(parents=True, exist_ok=True)
    temp = root / ".collection-status.tmp"
    temp.write_text(json.dumps(status))
    os.replace(temp, root / "collection-status.json")


def watch(hour=8, minute=15, zone="Europe/London", stop=None):
    stop = stop or threading.Event()
    if os.environ.get("IMPACT_DELIVERY_MODE") == "live_reader":
        schedule = Paths.from_env().home / "ops/schedule-status.json"
        schedule.parent.mkdir(parents=True, exist_ok=True)
        schedule.write_text(
            json.dumps(
                {
                    "installed": True,
                    "kind": "container_worker",
                    "local_time": f"{hour:02}:{minute:02}",
                    "timezone": zone,
                }
            )
        )
    while not stop.is_set():
        try:
            collect_once()
        except Exception:
            LOG.exception("Collection failed; keeping the previous public generation")
        delay = (
            next_daily(datetime.now(timezone.utc), hour, minute, zone) - datetime.now(timezone.utc)
        ).total_seconds()
        stop.wait(max(1, delay))
