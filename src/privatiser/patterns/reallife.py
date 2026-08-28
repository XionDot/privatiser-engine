"""Real-life patterns: vehicle plates, NHS, driving licences, bank details, tax refs, insurance."""

import re

from . import PatternHandler, register


# ============ VEHICLE REGISTRATION PLATES ============

register(
    # UK number plate (AB12 CDE or AB12CDE)
    PatternHandler(
        name="plate_uk",
        category="identifier",
        regex=re.compile(
            r"\b[A-Z]{2}\d{2}\s?[A-Z]{3}\b"
        ),
        pseudonym_fn=lambda n: f"XX00 XXX",
        priority=68,
    ),

    # US license plate (varies by state, common formats)
    PatternHandler(
        name="plate_us",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:plate|license\s*plate|tag|registration)[-.\s:]*"
            r"([A-Z0-9]{1,4}[-.\s]?[A-Z0-9]{2,5})"
        ),
        pseudonym_fn=lambda n: f"XXXX-{n:03d}",
        priority=68,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # EU plates (DE, FR, ES, IT, NL - context-aware)
    PatternHandler(
        name="plate_eu",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:plate|plaque|kennzeichen|targa|matricula|kenteken|immatriculation)[-.\s:]*"
            r"([A-Z0-9]{1,4}[-.\s]?[A-Z0-9]{1,4}[-.\s]?[A-Z0-9]{1,5})"
        ),
        pseudonym_fn=lambda n: f"XX-000-XX",
        priority=68,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ HEALTHCARE IDs ============

register(
    # UK NHS number (10 digits, often in groups of 3-3-4)
    PatternHandler(
        name="id_nhs",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:nhs|nhs\s+number|nhs\s+no)[-.\s:]*"
            r"(\d{3}[-.\s]?\d{3}[-.\s]?\d{4})"
        ),
        pseudonym_fn=lambda n: f"000 000 {n:04d}",
        priority=43,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # US Medicare/Medicaid ID (context-aware)
    PatternHandler(
        name="id_us_medicare",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:medicare|medicaid)[-.\s#:]*"
            r"([A-Z0-9]{4,12})"
        ),
        pseudonym_fn=lambda n: f"0000-000-{n:04d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # US health insurance policy number (context-aware)
    PatternHandler(
        name="id_insurance_policy",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:policy\s+(?:number|no|#)|insurance\s+id|member\s+id|"
            r"subscriber\s+id|group\s+(?:number|no|#)|plan\s+id)[-.\s#:]*"
            r"([A-Z0-9]{4,20})"
        ),
        pseudonym_fn=lambda n: f"POLICY-{n:06d}",
        priority=38,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # EU/UK VAT registration number (context-aware — a bare "GB123456789"
    # is too ambiguous with other IDs to match without the keyword)
    PatternHandler(
        name="id_vat",
        category="ssn",
        regex=re.compile(
            r"(?i)vat[_\s]*(?:reg(?:istration)?[_\s]*)?(?:number|no|id)?[-.\s#:]*"
            r"([A-Z]{2}\d{8,12}[A-Z]?)"
        ),
        pseudonym_fn=lambda n: f"VAT{n:09d}",
        priority=38,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ DRIVING LICENCES ============

register(
    # UK driving licence number (JONES710238AB9CD - surname + DOB encoded)
    PatternHandler(
        name="id_uk_driving",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:driving\s+licen[cs]e|driver'?s?\s+licen[cs]e|dvla)[-.\s#:]*"
            r"([A-Z]{5}\d{6}[A-Z0-9]{5})"
        ),
        pseudonym_fn=lambda n: f"XXXXX000000XX0XX",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # US driver's licence (context-aware, varies by state)
    PatternHandler(
        name="id_us_driving",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:driver'?s?\s+licen[cs]e|dl|dmv)[-.\s#:]*"
            r"([A-Z]?\d{4,12})"
        ),
        pseudonym_fn=lambda n: f"DL-0000{n:04d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ BANKING ============

register(
    # UK sort code (XX-XX-XX)
    PatternHandler(
        name="bank_sort_code",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:sort\s*code)[-.\s#:]*"
            r"(\d{2}[-.\s]?\d{2}[-.\s]?\d{2})"
        ),
        pseudonym_fn=lambda n: f"00-00-{n:02d}",
        priority=46,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # US/CA routing number (9 digits, context-aware)
    PatternHandler(
        name="bank_routing",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:routing|routing\s+number|aba|transit)[-.\s#:]*"
            r"(\d{9})\b"
        ),
        pseudonym_fn=lambda n: f"000000{n:03d}",
        priority=46,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Bank account number (context-aware)
    PatternHandler(
        name="bank_account",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:account\s*(?:number|no|#)|acct\s*(?:no|#)|bank\s+account|"
            r"checking|savings|current\s+account)[-.\s#:]*"
            r"(\d{6,18})"
        ),
        pseudonym_fn=lambda n: f"00000000{n:04d}",
        priority=46,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # SWIFT/BIC code (context-aware)
    PatternHandler(
        name="bank_swift",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:swift|bic|swift\s*code|bic\s*code)[-.\s#:]*"
            r"([A-Z]{6}[A-Z0-9]{2,5})"
        ),
        pseudonym_fn=lambda n: f"XXXXXX00",
        priority=46,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ TAX REFERENCES ============

register(
    # UK UTR (Unique Taxpayer Reference, 10 digits)
    PatternHandler(
        name="id_uk_utr",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:utr|unique\s+taxpayer\s+reference|tax\s+reference)[-.\s#:]*"
            r"(\d{10})\b"
        ),
        pseudonym_fn=lambda n: f"0000000{n:03d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # UK National Insurance number (AB 12 34 56 C)
    PatternHandler(
        name="id_uk_nino",
        category="ssn",
        regex=re.compile(
            r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b"
        ),
        pseudonym_fn=lambda n: f"XX 00 00 {n:02d} A",
        priority=44,
    ),

    # US EIN (Employer Identification Number: XX-XXXXXXX)
    PatternHandler(
        name="id_us_ein",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:ein|employer\s+id|fein|tax\s+id)[-.\s#:]*"
            r"(\d{2}-\d{7})"
        ),
        pseudonym_fn=lambda n: f"00-000{n:04d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # US ITIN (Individual Taxpayer Identification Number: 9XX-XX-XXXX)
    PatternHandler(
        name="id_us_itin",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:itin)[-.\s#:]*"
            r"(9\d{2}-\d{2}-\d{4})"
        ),
        pseudonym_fn=lambda n: f"900-00-{n:04d}",
        priority=44,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ INSURANCE ============

register(
    # US VIN (Vehicle Identification Number, 17 chars)
    PatternHandler(
        name="id_vin",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:vin|vehicle\s+identification)[-.\s#:]*"
            r"([A-HJ-NPR-Z0-9]{17})"
        ),
        pseudonym_fn=lambda n: f"00000000000000{n:03d}",
        priority=65,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Generic claim/reference number (context-aware)
    PatternHandler(
        name="id_claim_ref",
        category="identifier",
        regex=re.compile(
            r"(?i)(?:claim\s*(?:number|no|#|ref)|reference\s*(?:number|no|#)|"
            r"case\s*(?:number|no|#)|ticket\s*(?:number|no|#)|"
            r"invoice\s*(?:number|no|#)|order\s*(?:number|no|#)|"
            r"booking\s*(?:number|no|#|ref)|confirmation\s*(?:number|no|#)|"
            r"tracking\s*(?:number|no|#))[-.\s#:]*"
            r"([A-Z0-9][-A-Z0-9]{3,20})"
        ),
        pseudonym_fn=lambda n: f"REF-{n:06d}",
        priority=66,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)


# ============ CONTACT / PERSONAL ============

register(
    # Date of birth (context-aware)
    PatternHandler(
        name="dob",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:dob|date\s+of\s+birth|birthdate|birth\s+date|born\s+on|born)[-.\s:]*"
            r"(\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})"
        ),
        pseudonym_fn=lambda n: f"01/01/1990",
        priority=43,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Age (context-aware)
    PatternHandler(
        name="age",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:age|aged)[-.\s:]*"
            r"(\d{1,3})\s*(?:years?\s+old|yrs?\s+old|y\.?o\.?|years?|yrs?)?\b"
        ),
        pseudonym_fn=lambda n: f"[AGE]",
        priority=70,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Gender (context-aware)
    PatternHandler(
        name="gender",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:gender|sex)[-.\s:]*"
            r"(male|female|non-binary|nonbinary|other|m|f)\b"
        ),
        pseudonym_fn=lambda n: f"[GENDER]",
        priority=70,
        match_transform=lambda m: (m.group(1), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Nationality/ethnicity (context-aware)
    PatternHandler(
        name="nationality",
        category="ssn",
        regex=re.compile(
            r"(?i)\b(?:nationality|citizenship|ethnicity|race)\b[-.\s:]*"
            r"([A-Za-z][-A-Za-z\s]{2,25})"
        ),
        pseudonym_fn=lambda n: f"[NATIONALITY]",
        priority=70,
        match_transform=lambda m: (m.group(1).strip(), m.group(0)[:m.group(0).index(m.group(1))]),
    ),

    # Religion (context-aware)
    PatternHandler(
        name="religion",
        category="ssn",
        regex=re.compile(
            r"(?i)(?:religion|faith|religious\s+affiliation)[-.\s:]*"
            r"([A-Za-z][-A-Za-z\s]{2,25})"
        ),
        pseudonym_fn=lambda n: f"[RELIGION]",
        priority=70,
        match_transform=lambda m: (m.group(1).strip(), m.group(0)[:m.group(0).index(m.group(1))]),
    ),
)
