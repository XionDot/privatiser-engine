"""PII patterns: phone numbers, credit cards, SSN, passport, IBAN."""

import re

from . import PatternHandler, register


def _luhn_check(number: str) -> bool:
    """Validate a number string with the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _credit_card_validator(match: re.Match) -> bool:
    """Only anonymize numbers that pass Luhn check."""
    return _luhn_check(match.group(0))


def _ssn_validator(match: re.Match) -> bool:
    """Reject invalid SSN area numbers."""
    area = int(match.group(0)[:3])
    return area not in (0, 666) and area < 900


register(
    # US phone numbers (require formatting or +1 prefix)
    PatternHandler(
        name="phone_us",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:\+1[-.\s]?)?"
            r"\(?[2-9]\d{2}\)?[-.\s]"
            r"\d{3}[-.\s]?\d{4}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"(555) 000-{n:04d}",
        priority=45,
    ),

    # UK phone numbers
    PatternHandler(
        name="phone_uk",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:\+44[-.\s]?)"
            r"\d{4}[-.\s]?\d{6}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+44 7700 900{n:03d}",
        priority=45,
    ),

    # Credit card numbers (with optional separators, Luhn-validated)
    PatternHandler(
        name="credit_card",
        category="credit_card",
        regex=re.compile(
            r"\b(?:\d[ -]*?){13,19}\b"
        ),
        pseudonym_fn=lambda n: f"4000-0000-0000-{n:04d}",
        priority=47,
        validator=_credit_card_validator,
    ),

    # US Social Security Numbers
    PatternHandler(
        name="ssn",
        category="ssn",
        regex=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        pseudonym_fn=lambda n: f"078-05-{n:04d}",
        priority=44,
        validator=_ssn_validator,
    ),

    # Passport numbers (US format: 1 letter + 8 digits)
    PatternHandler(
        name="passport",
        category="passport",
        regex=re.compile(r"\b[A-Z]\d{8}\b"),
        pseudonym_fn=lambda n: f"X0000{n:04d}",
        priority=65,
    ),

    # IBAN (with or without spaces: GB29 NWBK 6016 1331 9268 19 or GB29NWBK60161331926819)
    PatternHandler(
        name="iban",
        category="iban",
        regex=re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b"),
        pseudonym_fn=lambda n: f"GB00XXXX0000000{n:05d}",
        priority=62,
    ),
)
