"""Bounded unambiguous JSON input for private local evidence tools."""

import json
import math


def loads(raw, *, budget, label="Evidence JSON"):
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeError:
            raise ValueError(label + " contains unsupported text encoding") from None
    if not isinstance(raw, (bytes, bytearray)):
        raise ValueError(label + " must be JSON text or bytes")
    if len(raw) > budget:
        raise ValueError(label + " exceeds its byte budget")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(label + " contains duplicate JSON keys")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError(label + " requires finite JSON numbers")

    def finite(value):
        parsed = float(value)
        return parsed if math.isfinite(parsed) else invalid(value)

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=finite)
    except (RecursionError, UnicodeError, json.JSONDecodeError):
        raise ValueError(label + " is not supported JSON") from None
