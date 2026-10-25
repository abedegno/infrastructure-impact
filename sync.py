"""Compatibility entry point. Prefer `impact sync` or `impact collect`."""
import sys
from infrastructure_impact.collection import service
if __name__=='__main__':
    from infrastructure_impact.cli import main
    main(['sync',*sys.argv[1:]])
else:
    sys.modules[__name__]=service
