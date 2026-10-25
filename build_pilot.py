"""Compatibility entry point; prefer the installed `impact` command."""
import importlib
import sys
if __name__=='__main__':
    from infrastructure_impact.cli import main
    main(['snapshot',*sys.argv[1:]])
else:
    sys.modules[__name__]=importlib.import_module('infrastructure_impact.application.publication')
