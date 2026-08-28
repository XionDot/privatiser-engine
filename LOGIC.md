# Privatiser — How It Works (Internal Reference)

Last updated: May 2026

> **Note:** `site/` (the privatiser.net website) lives in a separate, private
> repo and isn't part of this one. Where this doc says "sync from
> `site/privatiser.js`", treat `extension/src/privatiser.js` as the canonical
> copy within this repo instead — the site is just another downstream consumer
> of the same engine, not something you'll find here.

---

## Overview

Privatiser detects sensitive data using **regex-based pattern matching** and replaces it
with consistent pseudonyms. Every replacement is reversible via an encrypted mapping table.

Everything runs **100% locally** — no data is sent anywhere.

---

## Platform Architecture

```
privatiser/
├── extension/                   Browser extension (Chrome/Firefox/Edge)
│   ├── src/privatiser.js        Engine copy (synced from the canonical engine, lines 1-895)
│   ├── src/content.js           Intercepts paste/copy on AI chat sites
│   └── manifest.json
│
├── vscode-extension/            VS Code extension
│   ├── src/privatiser.js        Engine copy (synced from the canonical engine, lines 1-895)
│   └── package.json
│
└── src/privatiser/              Python package (PyPI: privatiser)
    ├── core.py                  Privatiser class (anonymize/deanonymize)
    ├── language.py              13-language detection + i18n secret keywords
    └── patterns/
        ├── secrets.py           API keys, JWTs, passwords, connection strings
        ├── network.py           IPs, emails, domains, MACs
        ├── pii.py               Credit cards, SSNs, IBANs, phones, passports
        ├── cloud.py             AWS/GCP/Azure resource IDs
        ├── identifiers.py       UUIDs, keyword-based identifiers
        ├── international.py     24 international patterns (phones, IDs, postcodes)
        ├── reallife.py          25 real-life patterns (NHS, SWIFT, plates, licences)
        └── names.py             First+last name detection (800-word dictionary)
```

---

## Engine Sync Rule

`extension/src/privatiser.js` and `vscode-extension/src/privatiser.js` should be kept
identical for their first 895 lines (the engine itself) — treat one as the source of
truth when you change a pattern, then copy those lines into the other:

```bash
head -895 extension/src/privatiser.js > /tmp/engine.js
cat /tmp/engine.js > vscode-extension/src/privatiser.js
echo "module.exports = { Privatiser };" >> vscode-extension/src/privatiser.js
```

The Python engine (`src/privatiser/`) is **maintained separately** but must stay in
sync with the JS patterns — same categories, same intent, even though the regex
syntax differs between the two languages.

---

## How Anonymization Works

### Two-Phase Replacement

1. **Phase 1 — Match & Placeholder**: Each pattern runs against the text (sorted by priority, highest first). When a match is found, the sensitive value is replaced with an internal null-byte placeholder (`\x00PRIV_N\x00`). This prevents later patterns from accidentally matching pseudonyms created by earlier patterns.

2. **Phase 2 — Placeholder to Pseudonym**: All placeholders are swapped for human-readable pseudonyms (e.g., `REDACTED_SECRET_1`, `10.0.1.2`, `user-1@redacted.example.net`).

### Duplicate Handling

Same value always gets the same pseudonym. Structural consistency preserved across the whole document.

### Deanonymization

Mapping sorted by pseudonym length (longest first) to prevent partial replacements, then each pseudonym replaced with its original value.

---

## How Each Platform Intercepts Sensitive Data

| Platform | Mechanism |
|---|---|
| Web (ChatGPT, Claude.ai etc.) | Browser extension intercepts paste/copy events |
| VS Code / Copilot | VS Code extension, Cmd+Shift+J anonymizes selection |

---

## Pattern Priority System

Higher priority number = processed first.

```
99  Private key blocks (-----BEGIN...)
95  AWS access keys (AKIA...)
93  Connection string credentials (://user:pass@)
92  JWTs (eyJ...)
90  Quoted secrets (keyword = "value")
89  Unquoted secrets (keyword = value)
88  Cloud tokens (GCP, Stripe, Slack, GitHub, Twilio)
85  Credit cards (Luhn-validated)
83  SSNs
80  IBANs
75  AWS secret keys (broad 40-char base64)
75  Emails
74  NHS numbers
72  Passports (with keyword)
71  Dates of birth (with keyword)
70  IPv4 addresses
65  Internal domains
60  Phone numbers (with separator)
55  UUIDs
```

---

## Multi-Language Detection

Supported languages: EN, FR, ES, DE, PT, IT, NL, RU, ZH, JA, KO, AR, HI (13 total)

Detection method:
- Script-range detection for non-Latin scripts (CJK, Cyrillic, Arabic, Devanagari, Hangul, Hiragana/Katakana)
- Word-frequency heuristic for Latin-script languages using marker word lists
- Threshold: 1 marker word hit triggers language detection
- All text NFC-normalised before comparison (prevents NFD/NFC mismatch for accented chars like ñ)

Once a language is detected, its secret keywords (e.g. `mot de passe`, `passwort`, `contraseña`) are injected as dynamic patterns with connectors:
- Punctuation: `=`, `:`
- Latin verbs: `is`, `est`, `ist`, `é`, `è`, `es`, `zijn`, `является`
- CJK particles: `是`, `は`, `が`, `를`, `은`, `는`, `です`, `है`

---

## Test Coverage

426 Python tests, covering:
- All pattern types (positive and negative)
- Roundtrip anonymize/deanonymize
- Luhn validation, SSN validation
- Adversarial inputs (ReDoS, placeholders, Unicode)
- 11-language natural language sentences
- Uppercase .env keys, connection string passwords
