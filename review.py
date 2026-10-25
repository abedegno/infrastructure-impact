"""Compatibility import; implementation lives in infrastructure_impact.application.disclosure."""
import importlib
import sys
sys.modules[__name__]=importlib.import_module("infrastructure_impact.application.disclosure")
