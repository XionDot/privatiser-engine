# Privatiser

**Now fully open source, MIT licensed.** Every feature that used to sit behind a paid
tier is free for everyone — no account, no licence key, nothing to unlock.

Anonymize sensitive content before sharing with AI. Redacts IPs, emails, API keys, passwords, and more — replacing them with structurally valid pseudonyms so AI analysis remains accurate. Fully reversible.

**Everything runs locally. Nothing leaves your machine.**

Available as a **Python CLI/library**, a **web UI**, and a **browser extension** for Chrome and Firefox.

## What it detects

| Category | Examples | Pseudonym format |
|---|---|---|
| IP addresses | `192.168.1.100`, `10.0.0.0/16` | `10.x.x.x` (preserves CIDR) |
| Email addresses | `admin@company.com` | `user-1@redacted.example.net` |
| Domain names | `prod-db.mycompany.com` | `redacted-host-1.example.net` |
| MAC addresses | `AA:BB:CC:DD:EE:FF` | `AA:BB:CC:00:00:01` |
| AWS Account IDs | `123456789012` | `100000000001` |
| AWS ARNs | `arn:aws:iam::123...:role/admin` | Structure preserved, values redacted |
| S3 buckets | `s3://my-prod-bucket` | `s3://redacted-bucket-1` |
| API keys | AWS, OpenAI, Anthropic, Google, Groq, GitHub, Slack | `REDACTED_SECRET_n` |
| Connection strings | `postgresql://user:pass@host/db` | `REDACTED_CONNSTR_n` |
| JWT tokens | `eyJhbG...` | `REDACTED_JWT_n` |
| PEM private keys | `-----BEGIN RSA PRIVATE KEY-----` | `REDACTED_PEM_KEY_n` |
| Generic secrets | `password = "value"` | Keyword preserved, value redacted |
| US phone numbers | `(555) 123-4567`, `+1-555-123-4567` | `(555) 000-0001` |
| UK phone numbers | `+44 7911 123456` | `+44 7700 900001` |
| Credit cards | `4111 1111 1111 1111` (Luhn validated) | `4000-0000-0000-0001` |
| US SSN | `123-45-6789` | `078-05-0001` |
| Passports | `C12345678` | `X00000001` |
| IBAN | `DE89370400440532013000` | `GB00XXXX000000000001` |
| UUIDs | `550e8400-e29b-41d4-...` | `00000000-0000-4000-a000-...` |

Skips well-known values: `127.0.0.1`, `0.0.0.0`, cloud provider domains (`amazonaws.com`, `github.com`, etc.).

## Installation

```bash
pip install privatiser
```

For the web UI:
```bash
pip install privatiser[web]
```

## Usage

### CLI

```bash
# Anonymize from stdin
cat config.tf | privatiser anonymize

# Anonymize a file, save mapping
privatiser anonymize config.tf -o clean.tf -m mapping.json

# Anonymize from clipboard
privatiser anonymize -c -m mapping.json

# Anonymize .env files (preserves keys, redacts values)
privatiser anonymize .env --env -m mapping.json

# Disable specific categories
privatiser anonymize config.tf -d pii -d aws

# Skip specific values
privatiser anonymize config.tf --allowlist allow.txt

# Restore original content
privatiser deanonymize clean.tf -m mapping.json

# Launch web UI
privatiser ui
privatiser ui --port 8080 --debug
```

### Python API

```python
from privatiser import Privatiser

p = Privatiser()

# Anonymize
text = 'server = "192.168.1.100"\npassword = "secret123"'
anonymized, mapping = p.anonymize(text)
print(anonymized)
# server = "10.0.1.8"
# password = "REDACTED_SECRET_1"

# Restore
restored = p.deanonymize(anonymized, mapping)
assert restored == text  # Perfect round-trip

# Works on nested data structures too
data = {"servers": [{"ip": "10.0.1.8"}]}
restored_data = p.deanonymize_data(data, mapping)
```

### Custom patterns

```python
from privatiser import Privatiser, register_custom

register_custom("ticket_id", r"TICKET-\d{4,6}", "REDACTED_TICKET_{n}")

p = Privatiser()
result, mapping = p.anonymize("Fix TICKET-12345")
# result: "Fix REDACTED_TICKET_1"
```

### Web UI

```bash
privatiser ui
```

Opens at `http://127.0.0.1:7860`. Two tabs:

- **Anonymize** — Paste text, click Anonymize, copy the safe output. Mapping table shows what was redacted.
- **Deanonymize** — Paste anonymized text + mapping JSON, restore originals.

Dark/light theme. Keyboard shortcut: `Ctrl+Enter` to process.

### Browser extension

The extension is available for [Chrome](https://chrome.google.com/webstore) and [Firefox](https://addons.mozilla.org/firefox/addon/privatiser/).

#### Auto-intercept (paste protection)

When enabled (on by default), the extension automatically anonymizes anything you paste into supported AI chat sites:

- **ChatGPT** (chatgpt.com / chat.openai.com)
- **Claude** (claude.ai)
- **Gemini** (gemini.google.com)
- **Copilot** (copilot.microsoft.com)

#### Auto-deanonymize (copy restoration)

When copying text from an AI response that contains pseudonyms, the extension automatically restores the original values to your clipboard.

#### Popup (manual mode)

Click the Privatiser icon in your toolbar. Three tabs:

- **Anonymize** — Paste sensitive text, click Anonymize, copy the cleaned output.
- **Restore** — Paste anonymized text + the mapping JSON to get back the originals.
- **Settings** — Toggle auto-intercept, auto-deanonymize, category toggles, and allowlist.

#### Right-click menu

Select any text on any page, right-click, and choose **"Anonymize with Privatiser"** or **"Deanonymize with Privatiser"**.

### Typical AI workflow

```
┌─────────────┐    paste    ┌──────────────┐    send    ┌─────────┐
│ Your config │ ──────────► │  Extension   │ ────────► │  AI Chat │
│ with real   │             │  auto-redacts │           │  sees    │
│ IPs, keys   │             │  on paste     │           │  safe    │
│ passwords   │             │               │           │  pseudos │
└─────────────┘             └──────┬───────┘           └────┬────┘
                                   │                        │
                            mapping saved              AI responds
                            in session                 with pseudos
                                   │                        │
                                   ▼                        ▼
                            ┌──────────────┐    restore  ┌─────────┐
                            │ Restore tab  │ ◄────────── │  Copy   │
                            │ + mapping    │             │  AI     │
                            │ = originals  │             │  output │
                            └──────────────┘             └─────────┘
```

## Security

- All processing happens locally — no network requests, no external services
- The browser extension only activates on specific AI chat domains
- Mapping data uses session storage (cleared when browser closes)
- No data is persisted unless you explicitly enable "Remember mappings" in settings

## Links

- Website: [privatiser.net](https://privatiser.net)
- Firefox: [addons.mozilla.org/firefox/addon/privatiser/](https://addons.mozilla.org/firefox/addon/privatiser/)
- PyPI: [pypi.org/project/privatiser/](https://pypi.org/project/privatiser/)

## Roadmap

- **Custom regex patterns** (web tool) — define your own regex alongside plain custom words (e.g. `PROJ-\d+`, internal ID formats)
- **Saved profiles** — store named configs in localStorage ("Work", "Client A") with different custom words, allowlists, and category toggles
- **Settings import/export** — download config as JSON, import it back; useful for sharing a team config
- **Pattern hit highlighting** — colour-coded highlights in the input showing which category matched each value
- **Clipboard auto-redact** (browser extension) — redact on copy rather than on paste, so data never reaches the clipboard unredacted
- **VS Code: redact on save** — optional mode that writes a `.redacted` copy of a file on save
- **Professional profiles** — industry-specific redaction profiles with pre-built patterns tailored to a profession (legal, medical/healthcare, finance, DevOps/infrastructure). User describes their format or selects their profession, gets a ready-made profile they can customise and save locally.

## Support

Privatiser is free and open source — every feature, no account, no licence key. If you'd like to support development, crypto donations are on the [pricing page](https://privatiser.net/pricing.html), or [Buy Me a Coffee](https://buymeacoffee.com/cr4ne).

For questions about deploying this for a team: [admin@privatiser.net](mailto:admin@privatiser.net)

## License

MIT
