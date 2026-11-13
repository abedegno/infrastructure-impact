"""Opt-in release ordering for analysis, never automatic product matching."""

import re


def version_key(vendor: str, literal: str) -> tuple | None:
    """Accept whole supported ASCII literals without whitespace or case coercion."""
    if not isinstance(literal, str) or len(literal) > 128:
        return None
    if vendor == "cisco":
        match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)([abc]?)", literal)
        if match:
            return (*map(int, match.group(1, 2, 3)), "abc".find(match[4]) + 1 if match[4] else 0)
    elif vendor == "aruba":
        if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", literal):
            return tuple(map(int, literal.split(".")))
    elif vendor == "arista":
        match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)([FM]?)", literal)
        if match:
            return (*map(int, match[1].split(".")), match[2])
    return None


def release_train(vendor: str, literal: str) -> str | None:
    key = version_key(vendor, literal)
    return f"{key[0]}.{key[1]}" if key is not None else None


def compare_releases(vendor: str, left: str, right: str) -> int | None:
    """Compare within a train; equal-number EOS variants do not imply precedence."""
    a, b = version_key(vendor, left), version_key(vendor, right)
    if a is None or b is None or a[:2] != b[:2]:
        return None
    if vendor == "arista":
        # Component counts have no approved equivalence (e.g. 1 versus 1.0).
        if len(a) != len(b) or (a[:-1] == b[:-1] and a[-1] != b[-1]):
            return None
        a, b = a[:-1], b[:-1]
    return (a > b) - (a < b)
