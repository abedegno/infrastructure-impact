"""Registration of the bundled vendor implementations."""

from importlib import import_module


def builtin_plugins():
    for name in (
        "cisco",
        "aruba",
        "arista",
        "paloalto",
        "juniper",
        "checkpoint",
        "fortinet",
        "hpe",
    ):
        yield import_module(f"{__package__}.{name}").plugin()
