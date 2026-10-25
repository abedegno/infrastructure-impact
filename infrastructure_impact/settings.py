"""Explicit filesystem configuration shared by CLI, workers and the API."""

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Paths:
    home: Path
    database: Path
    sources: Path
    snapshot: Path
    publications: Path

    @classmethod
    def from_env(cls):
        home = Path(os.environ.get("IMPACT_HOME", Path.cwd())).resolve()
        return cls(
            home=home,
            database=Path(os.environ.get("IMPACT_DATABASE", home / "data/intel.sqlite3")),
            sources=Path(os.environ.get("IMPACT_SOURCES", home / "sources.json")),
            snapshot=Path(os.environ.get("IMPACT_SNAPSHOT", home / "site/dist")),
            publications=Path(os.environ.get("IMPACT_PUBLICATIONS", home / "publications")),
        )
