"""Core Privatiser class - the main anonymization engine."""

from __future__ import annotations

import re
from collections import defaultdict

from .language import detect_languages, get_secret_keywords
from .patterns import PatternHandler, get_all_handlers

# Placeholder format that won't match any pattern
_PLACEHOLDER_PREFIX = "\x00PRIV_"
_PLACEHOLDER_SUFFIX = "\x00"

# Category groups map group names to pattern category values
CATEGORY_GROUPS: dict[str, set[str]] = {
    "secrets": {"secret"},
    "network": {"ip", "domain", "email", "mac", "url"},
    "pii": {"phone", "credit_card", "ssn", "passport", "iban"},
    "aws": {"account", "arn", "bucket"},
    "cloud": {"cloud"},
    "identifiers": {"uuid"},
}


def _i18n_secret_transform(match: re.Match) -> tuple[str, str]:
    prefix = match.group(1)
    value = match.group(2)
    return value, prefix


def _i18n_secret_validator(match: re.Match) -> bool:
    value = match.group(2)
    return not value.startswith("REDACTED_")


def _build_i18n_secret_handlers(keywords: list[str]) -> list[PatternHandler]:
    """Build secret pattern handlers from translated keywords."""
    if not keywords:
        return []

    escaped = [re.escape(k) for k in keywords]
    joined = "|".join(escaped)
    # Connectors: punctuation (with optional surrounding spaces), Latin-script
    # "to be" verbs (require leading space), CJK particles (no leading space needed)
    conn = r"(?:\s*[=:]\s*|\s+(?:is|est|ist|é|è|es|zijn|является)\s*|\s*(?:是|は|が|를|은|는|です|है)\s*)"

    return [
        # Quoted: keyword is/= "value"
        PatternHandler(
            name="i18n_secret",
            category="secret",
            regex=re.compile(
                rf"((?:{joined}){conn}\s*[\"'])"
                rf"([^\"']{{4,}})"
                rf"(?=[\"'])",
                re.IGNORECASE,
            ),
            pseudonym_fn=lambda n: f"REDACTED_SECRET_{n}",
            priority=41,
            match_transform=_i18n_secret_transform,
            validator=_i18n_secret_validator,
        ),
        # Unquoted: keyword is/= value
        PatternHandler(
            name="i18n_secret_unquoted",
            category="secret",
            regex=re.compile(
                rf"((?:{joined}){conn}\s*)"
                rf"([^\s\"']{{4,}})",
                re.IGNORECASE,
            ),
            pseudonym_fn=lambda n: f"REDACTED_SECRET_{n}",
            priority=40,
            match_transform=_i18n_secret_transform,
            validator=_i18n_secret_validator,
        ),
    ]


class Privatiser:
    """Anonymizes sensitive content with reversible pseudonyms.

    Usage:
        p = Privatiser()
        anonymized, mapping = p.anonymize(text)
        restored = p.deanonymize(anonymized, mapping)
        assert restored == text
    """

    def __init__(
        self,
        extra_patterns: list[PatternHandler] | None = None,
        enabled_categories: dict[str, bool] | None = None,
        allowlist: list[str] | None = None,
    ):
        self._mapping: dict[str, str] = {}      # original -> pseudonym
        self._reverse: dict[str, str] = {}       # pseudonym -> original
        self._counters: dict[str, int] = defaultdict(lambda: 1)
        self._enabled_categories = enabled_categories or {}
        self._allowlist = allowlist or []

        self._handlers = get_all_handlers()
        if extra_patterns:
            self._handlers = self._handlers + extra_patterns
            self._handlers.sort(key=lambda h: h.priority)

        # Filter by enabled categories
        if self._enabled_categories:
            self._handlers = [
                h for h in self._handlers if self._is_category_enabled(h.category)
            ]

    def anonymize(self, content: str) -> tuple[str, dict[str, str]]:
        """Anonymize sensitive data in content.

        Returns:
            (anonymized_content, mapping) where mapping is {pseudonym: original}
        """
        # Detect languages and inject translated secret keywords
        handlers = self._handlers
        langs = detect_languages(content)
        if langs - {"en"}:
            extra_keywords = get_secret_keywords(langs)
            if extra_keywords:
                handlers = handlers + _build_i18n_secret_handlers(extra_keywords)
                handlers.sort(key=lambda h: h.priority)

        # Phase 1: Replace matches with null-byte placeholders so later
        # patterns don't re-match pseudonyms from earlier patterns.
        placeholders: dict[str, str] = {}  # placeholder -> pseudonym
        result = content

        for handler in handlers:
            result = handler.regex.sub(
                lambda m, h=handler: self._apply_handler(m, h, placeholders), result
            )

        # Phase 2: Replace placeholders with actual pseudonyms
        for placeholder, pseudonym in placeholders.items():
            result = result.replace(placeholder, pseudonym)

        return result, dict(self._reverse)

    def deanonymize(self, content: str, mapping: dict[str, str] | None = None) -> str:
        """Replace pseudonyms back to original values."""
        if not content:
            return content
        m = mapping or self._reverse
        if not m:
            return content
        result = content
        # Sort by length descending to avoid partial replacements
        for pseudonym, original in sorted(m.items(), key=lambda x: len(x[0]), reverse=True):
            result = result.replace(pseudonym, original)
        return result

    def deanonymize_data(self, data, mapping: dict[str, str] | None = None):
        """Recursively deanonymize all string values in a dict/list structure."""
        m = mapping or self._reverse
        if not m:
            return data
        if isinstance(data, str):
            return self.deanonymize(data, m)
        elif isinstance(data, dict):
            return {k: self.deanonymize_data(v, m) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.deanonymize_data(item, m) for item in data]
        return data

    def get_mapping(self) -> dict[str, str]:
        """Return the current pseudonym -> original mapping."""
        return dict(self._reverse)

    def reset(self) -> None:
        """Clear all state (mappings and counters)."""
        self._mapping.clear()
        self._reverse.clear()
        self._counters.clear()

    def _is_category_enabled(self, category: str) -> bool:
        """Check if a pattern category is enabled."""
        for group, cats in CATEGORY_GROUPS.items():
            if category in cats:
                return self._enabled_categories.get(group, True)
        return True  # Unknown categories enabled by default

    def _is_allowlisted(self, value: str) -> bool:
        """Check if a value is in the allowlist (exact match only)."""
        return value in self._allowlist

    def _make_placeholder(self, pseudonym: str, placeholders: dict[str, str]) -> str:
        """Create a unique placeholder for a pseudonym."""
        idx = len(placeholders)
        placeholder = f"{_PLACEHOLDER_PREFIX}{idx}{_PLACEHOLDER_SUFFIX}"
        placeholders[placeholder] = pseudonym
        return placeholder

    def _apply_handler(
        self, match: re.Match, handler: PatternHandler, placeholders: dict[str, str]
    ) -> str:
        """Apply a pattern handler to a regex match."""
        # Skip if match contains a placeholder (already processed by earlier pattern)
        if _PLACEHOLDER_PREFIX in match.group(0):
            return match.group(0)

        # Check allowlist
        if self._is_allowlisted(match.group(0)):
            return match.group(0)

        # Run validator if present
        if handler.validator and not handler.validator(match):
            return match.group(0)

        # Handle ARN structure preservation
        if handler.name == "arn":
            pseudonym = self._anonymize_arn(match.group(0), handler)
            return self._make_placeholder(pseudonym, placeholders)

        # Extract value and prefix
        if handler.match_transform:
            value, prefix = handler.match_transform(match)
        else:
            value, prefix = match.group(0), ""

        # Handle CIDR suffix for IPs
        cidr_suffix = ""
        if handler.name == "ipv4" and "/" in match.group(0):
            raw = match.group(0)
            value, cidr_suffix = raw.rsplit("/", 1)
            cidr_suffix = "/" + cidr_suffix

        pseudonym = self._get_or_create(value, handler)
        full = f"{prefix}{pseudonym}{cidr_suffix}"
        return self._make_placeholder(full, placeholders)

    def _get_or_create(self, value: str, handler: PatternHandler) -> str:
        """Get existing pseudonym or create a new one."""
        if value in self._mapping:
            return self._mapping[value]

        n = self._counters[handler.category]
        pseudonym = handler.pseudonym_fn(n)
        self._counters[handler.category] = n + 1
        self._mapping[value] = pseudonym
        self._reverse[pseudonym] = value
        return pseudonym

    def _anonymize_arn(self, original: str, handler: PatternHandler) -> str:
        """Preserve ARN structure while anonymizing account + resource."""
        if original in self._mapping:
            return self._mapping[original]

        parts = original.split(":")
        if len(parts) >= 6:
            service = parts[2]
            region = parts[3]
            resource = parts[5] if len(parts) > 5 else "resource"
            resource_type = ""
            if "/" in resource:
                resource_type = resource.split("/")[0] + "/"

            n = self._counters[handler.category]
            pseudonym = f"arn:aws:{service}:{region}:{100000000000 + n}:{resource_type}redacted-{n}"
            self._counters[handler.category] = n + 1
            self._mapping[original] = pseudonym
            self._reverse[pseudonym] = original
            return pseudonym
        return original
