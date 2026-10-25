"""Compatibility import; implementation lives in infrastructure_impact.storage.repository."""
import importlib
import sys
sys.modules[__name__]=importlib.import_module("infrastructure_impact.storage.repository")
