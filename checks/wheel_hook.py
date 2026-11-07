"""Duplicate the canonical codec in wheels without reserving its package path."""

import shutil
import tempfile
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CanonicalCodecHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # Hatch reserves in-tree force-include sources and omits their normal
        # package paths. Only this temporary file is forced; the canonical
        # source remains in normal package selection.
        self._temporary = tempfile.TemporaryDirectory(prefix="impact-wheel-codec-")
        try:
            target = Path(self._temporary.name) / "publication_codec.py"
            shutil.copyfile(Path(self.root) / "infrastructure_impact/publication_codec.py", target)
            build_data["force_include"][str(target)] = (
                "infrastructure_impact/_standalone/publication_codec.py"
            )
        except BaseException:
            self._temporary.cleanup()
            raise

    def finalize(self, version, build_data, artifact_path):
        self._temporary.cleanup()
