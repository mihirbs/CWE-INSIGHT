# Author: Mihir Brijesh Solanki (40481948)
"""Input validation for API query parameters.

We validate everything with plain Python — no external library needed.
The approach is an allowlist: only values we explicitly list are accepted,
everything else gets rejected. Makes it easy to see exactly what's allowed.
"""
from __future__ import annotations

from dataclasses import dataclass, field

_VALID_LIKELIHOODS = frozenset({"High", "Medium", "Low"})
_VALID_ABSTRACTIONS = frozenset({"Class", "Base", "Variant", "Compound"})
_KNOWN_SEARCH_PARAMS = frozenset({"platform", "likelihood", "abstraction", "limit", "offset"})

_CWE_ID_MIN = 1
_CWE_ID_MAX = 9999
_PLATFORM_MAX_LEN = 50  # cap platform strings so nobody sends a huge payload
_LIMIT_DEFAULT = 20
_LIMIT_MAX = 100


@dataclass
class ValidationError(Exception):
    """Raised when input validation fails. Carries structured error details."""

    messages: dict = field(default_factory=dict)

    def __str__(self):
        return str(self.messages)


def validate_cwe_id(cwe_id: int) -> int:
    """Check that a CWE ID is in the valid range (1–9999)."""
    if not (_CWE_ID_MIN <= cwe_id <= _CWE_ID_MAX):
        raise ValidationError(
            {"cwe_id": f"Must be between {_CWE_ID_MIN} and {_CWE_ID_MAX}"}
        )
    return cwe_id


def validate_search_params(args: dict) -> dict:
    """Validate and clean up search query parameters.

    Rejects unknown parameters outright — if someone passes something we
    don't recognise, it's better to error than to silently ignore it.
    """
    errors = {}

    unknown = set(args.keys()) - _KNOWN_SEARCH_PARAMS
    if unknown:
        errors["unknown_params"] = f"Unknown parameters not allowed: {sorted(unknown)}"
        raise ValidationError(errors)

    platform = None
    if "platform" in args:
        raw = args["platform"].strip()
        if len(raw) > _PLATFORM_MAX_LEN:
            errors["platform"] = f"Must be {_PLATFORM_MAX_LEN} characters or fewer"
        else:
            platform = raw if raw else None

    likelihood = None
    if "likelihood" in args:
        raw = args["likelihood"].strip()
        if raw not in _VALID_LIKELIHOODS:
            errors["likelihood"] = f"Must be one of: {sorted(_VALID_LIKELIHOODS)}"
        else:
            likelihood = raw

    abstraction = None
    if "abstraction" in args:
        raw = args["abstraction"].strip()
        if raw not in _VALID_ABSTRACTIONS:
            errors["abstraction"] = f"Must be one of: {sorted(_VALID_ABSTRACTIONS)}"
        else:
            abstraction = raw

    limit = _LIMIT_DEFAULT
    if "limit" in args:
        try:
            limit = int(args["limit"])
        except ValueError:
            errors["limit"] = "Must be an integer"
        else:
            if not (1 <= limit <= _LIMIT_MAX):
                errors["limit"] = f"Must be between 1 and {_LIMIT_MAX}"

    offset = 0
    if "offset" in args:
        try:
            offset = int(args["offset"])
        except ValueError:
            errors["offset"] = "Must be an integer"
        else:
            if offset < 0:
                errors["offset"] = "Must be 0 or greater"

    if errors:
        raise ValidationError(errors)

    return {
        "platform": platform,
        "likelihood": likelihood,
        "abstraction": abstraction,
        "limit": limit,
        "offset": offset,
    }
