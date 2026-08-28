"""International patterns: country-specific phones, IDs, postcodes, dates."""

import re

from . import PatternHandler, register


# ============ PHONE NUMBERS ============

register(
    # French phone numbers: +33 or 0 + 9 digits
    PatternHandler(
        name="phone_fr",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:\+33[-.\s]?|0)"
            r"[1-9](?:[-.\s]?\d{2}){4}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+33 6 00 00 {n:04d}",
        priority=45,
    ),

    # German phone numbers: +49 or 0 + area + number
    PatternHandler(
        name="phone_de",
        category="phone",
        regex=re.compile(
            r"(?<!\w)"
            r"(?:\+49[-.\s]?|0)"
            r"\d{2,5}[-.\s]?\d{3,8}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+49 30 000{n:04d}",
        priority=45,
    ),

    # Spanish phone numbers: +34 + 9 digits
    PatternHandler(
        name="phone_es",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"\+34[-.\s]?"
            r"[6-9]\d{2}[-.\s]?\d{3}[-.\s]?\d{3}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+34 600 000 {n:03d}",
        priority=45,
    ),

    # Italian phone numbers: +39 + 10 digits
    PatternHandler(
        name="phone_it",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"\+39[-.\s]?"
            r"3\d{2}[-.\s]?\d{3}[-.\s]?\d{4}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+39 300 000 {n:04d}",
        priority=45,
    ),

    # Brazilian phone numbers: +55 + DDD + 8-9 digits
    PatternHandler(
        name="phone_br",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"\+55[-.\s]?"
            r"\d{2}[-.\s]?"
            r"9?\d{4}[-.\s]?\d{4}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+55 11 90000 {n:04d}",
        priority=45,
    ),

    # Indian phone numbers: +91 + 10 digits
    PatternHandler(
        name="phone_in",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:\+91[-.\s]?|0)"
            r"[6-9]\d{9}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+91 90000 {n:05d}",
        priority=45,
    ),

    # Australian phone numbers: +61 or 0 + 9 digits
    PatternHandler(
        name="phone_au",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:\+61[-.\s]?|0)"
            r"4\d{2}[-.\s]?\d{3}[-.\s]?\d{3}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+61 400 000 {n:03d}",
        priority=45,
    ),

    # Japanese phone numbers: +81 or 0 + area + number
    PatternHandler(
        name="phone_jp",
        category="phone",
        regex=re.compile(
            r"(?<!\d)"
            r"(?:\+81[-.\s]?|0)"
            r"[1-9]0[-.\s]?\d{4}[-.\s]?\d{4}"
            r"(?!\d)"
        ),
        pseudonym_fn=lambda n: f"+81 90 0000 {n:04d}",
        priority=45,
    ),

    # Canadian phone numbers (same format as US but +1 required for distinction)
    # Handled by existing phone_us pattern
)


# ============ NATIONAL IDs ============

register(
    # French INSEE / Social Security (1 or 2 + 13 digits)
    PatternHandler(
        name="id_fr_insee",
        category="ssn",
        regex=re.compile(
            r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b"
        ),
        pseudonym_fn=lambda n: f"1 00 00 00 000 {n:03d} 00",
        priority=44,
    ),

    # German tax ID (Steuerliche Identifikationsnummer: 11 digits)
    PatternHandler(
        name="id_de_steuerid",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:steuer[-\s]?id(?:entifikationsnummer)?|tin)[-.\s:]*"
            r"(\d{2}\s?\d{3}\s?\d{3}\s?\d{3})"
        ),
        pseudonym_fn=lambda n: f"00 000 000 {n:03d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Indian Aadhaar (12 digits in groups of 4, context-aware)
    PatternHandler(
        name="id_in_aadhaar",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:aadhaar|aadhar|uidai)[-.\s:]*"
            r"([2-9]\d{3}[-.\s]?\d{4}[-.\s]?\d{4})"
        ),
        pseudonym_fn=lambda n: f"2000 0000 {n:04d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Indian PAN (5 letters + 4 digits + 1 letter)
    PatternHandler(
        name="id_in_pan",
        category="ssn",
        regex=re.compile(
            r"\b[A-Z]{5}\d{4}[A-Z]\b"
        ),
        pseudonym_fn=lambda n: f"AAAAA0000A",
        priority=65,
    ),

    # Canadian SIN (9 digits in groups of 3)
    PatternHandler(
        name="id_ca_sin",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:sin|social\s+insurance)[-.\s:]*"
            r"(\d{3}[-.\s]?\d{3}[-.\s]?\d{3})"
        ),
        pseudonym_fn=lambda n: f"000-000-{n:03d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Australian Tax File Number (8-9 digits)
    PatternHandler(
        name="id_au_tfn",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:tfn|tax\s+file\s+number)[-.\s:]*"
            r"(\d{3}[-.\s]?\d{3}[-.\s]?\d{2,3})"
        ),
        pseudonym_fn=lambda n: f"000 000 {n:03d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Australian Medicare number (10-11 digits)
    PatternHandler(
        name="id_au_medicare",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:medicare)[-.\s:]*"
            r"(\d{4}[-.\s]?\d{5}[-.\s]?\d{1,2})"
        ),
        pseudonym_fn=lambda n: f"0000 00000 {n}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ POSTCODES ============

register(
    # UK postcode (already partially handled by identifiers, but explicit)
    PatternHandler(
        name="postcode_uk",
        category="identifier",
        regex=re.compile(
            r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"XX{n} 0XX",
        priority=70,
    ),

    # German PLZ (5 digits, context-aware)
    PatternHandler(
        name="postcode_de",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:plz|postleitzahl|postal)[-.\s:]*(\d{5})\b"
        ),
        pseudonym_fn=lambda n: f"0000{n}",
        priority=70,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # French postal code (5 digits, context-aware)
    PatternHandler(
        name="postcode_fr",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:code\s+postal|cp)[-.\s:]*(\d{5})\b"
        ),
        pseudonym_fn=lambda n: f"7500{n}",
        priority=70,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Japanese postal code (〒NNN-NNNN - requires 〒 symbol as context)
    PatternHandler(
        name="postcode_jp",
        category="identifier",
        regex=re.compile(
            r"\u3012\s?(\d{3}-\d{4})"
        ),
        pseudonym_fn=lambda n: f"\u3012000-{n:04d}",
        priority=70,
        match_transform=lambda m: (m.group(1), "\u3012"),
    ),

    # Canadian postal code (A1A 1A1)
    PatternHandler(
        name="postcode_ca",
        category="identifier",
        regex=re.compile(
            r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"X0X 0X{n}",
        priority=70,
    ),

    # Indian PIN code (6 digits, context-aware)
    PatternHandler(
        name="postcode_in",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:pin\s*code|pincode|postal)[-.\s:]*(\d{6})\b"
        ),
        pseudonym_fn=lambda n: f"10000{n}",
        priority=70,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ DATE FORMATS ============

register(
    # EU date format: DD/MM/YYYY or DD.MM.YYYY or DD-MM-YYYY
    PatternHandler(
        name="date_eu",
        category="identifier",
        regex=re.compile(
            r"\b(?:0[1-9]|[12]\d|3[01])[/.\-](?:0[1-9]|1[0-2])[/.\-](?:19|20)\d{2}\b"
        ),
        pseudonym_fn=lambda n: f"01/01/2000",
        priority=72,
    ),

    # East Asian date format: YYYY/MM/DD or YYYY-MM-DD
    PatternHandler(
        name="date_iso",
        category="identifier",
        regex=re.compile(
            r"\b(?:19|20)\d{2}[/\-](?:0[1-9]|1[0-2])[/\-](?:0[1-9]|[12]\d|3[01])\b"
        ),
        pseudonym_fn=lambda n: f"2000-01-01",
        priority=72,
    ),
)
