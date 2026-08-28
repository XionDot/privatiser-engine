# Privatiser for VS Code

Anonymize sensitive data (IPs, API keys, passwords, PII, cloud identifiers) directly in your editor before sharing with AI assistants.

## Features

- Detects 100+ secret keywords, API key formats, JWTs, PEM keys, connection strings
- Redacts IPs, emails, domains, phone numbers, credit cards, SSNs
- Recognizes AWS ARNs, S3 buckets, Azure subscriptions, GCP projects
- Keyword-based identifier detection (hostnames, usernames, paths, addresses)
- Reversible: deanonymize to restore original values
- 100% local — nothing leaves your machine

## Usage

1. Select text containing sensitive data
2. Right-click and choose **Privatiser: Anonymize Selection** (or press `Ctrl+Shift+A` / `Cmd+Shift+A`)
3. The selected text is replaced with anonymized pseudonyms
4. Copy and paste into your AI tool
5. Paste the AI response back, select it, and choose **Privatiser: Deanonymize Selection** (`Ctrl+Shift+D` / `Cmd+Shift+D`)

**Prefer to keep your file untouched?** Use **Copy Anonymized Selection** (`Ctrl+Shift+J` / `Cmd+Shift+J`) to copy the anonymized version to clipboard without modifying the editor.

## Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| Privatiser: Anonymize Selection | `Ctrl+Shift+A` / `Cmd+Shift+A` | Anonymize selected text in place |
| Privatiser: Copy Anonymized Selection | `Ctrl+Shift+J` / `Cmd+Shift+J` | Copy anonymized version to clipboard, file unchanged |
| Privatiser: Anonymize Entire File | `Ctrl+Alt+A` / `Cmd+Alt+A` | Anonymize the entire document |
| Privatiser: Deanonymize Selection | `Ctrl+Shift+D` / `Cmd+Shift+D` | Restore original values in selection |
| Privatiser: Deanonymize Entire File | `Ctrl+Alt+D` / `Cmd+Alt+D` | Restore original values in entire document |

## How It Works

Privatiser uses regex-based pattern matching to detect sensitive values and replaces them with consistent pseudonyms. The mapping is stored per-file in your workspace so you can deanonymize later.

All processing happens locally in your VS Code instance. No data is sent anywhere.
