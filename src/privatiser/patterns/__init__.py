"""Pattern handler registry for Privatiser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

# Type for match_transform: takes a Match, returns (value_to_anonymize, prefix_to_preserve)
MatchTransform = Callable[[re.Match], tuple[str, str]]


@dataclass
class PatternHandler:
    """A single anonymization pattern."""

    name: str
    category: str  # counter bucket (e.g. "ip", "phone", "secret")
    regex: re.Pattern
    pseudonym_fn: Callable[[int], str]
    priority: int = 50  # lower = matched first (more specific)
    # Optional transform: extract (value, prefix) from a match.
    # If None, entire match.group(0) is the value, prefix is "".
    match_transform: MatchTransform | None = None
    # Optional validator: return True if match should be anonymized.
    validator: Callable[[re.Match], bool] | None = None


_registry: list[PatternHandler] = []


def register(*handlers: PatternHandler) -> None:
    """Register one or more pattern handlers."""
    _registry.extend(handlers)
    _registry.sort(key=lambda h: h.priority)


def get_all_handlers() -> list[PatternHandler]:
    """Return all registered handlers, sorted by priority."""
    return list(_registry)
