"""Compatibility import; implementation lives in infrastructure_impact.adapters.compat."""
import importlib
import sys
sys.modules[__name__]=importlib.import_module("infrastructure_impact.adapters.compat")
