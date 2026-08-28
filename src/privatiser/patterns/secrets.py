"""Secret/credential patterns: API keys, connection strings, JWT, PEM, generic secrets."""

import re

from . import PatternHandler, register


def _secret_value_transform(match: re.Match) -> tuple[str, str]:
    """For 'password = "value"' patterns, anonymize only the value, keep the prefix."""
    prefix = match.group(1)  # e.g. 'password = "'
    value = match.group(2)   # the actual secret
    return value, prefix


def _secret_value_validator(match: re.Match) -> bool:
    """Skip already-redacted values."""
    value = match.group(2)
    return not value.startswith("REDACTED_")


def _connection_string_pseudonym(n: int) -> str:
    return f"REDACTED_CONNSTR_{n}"


def _connection_string_transform(match: re.Match) -> tuple[str, str]:
    """Preserve the protocol prefix in the pseudonym."""
    original = match.group(0)
    protocol = original.split("://")[0]
    return original, ""


def _bearer_transform(match: re.Match) -> tuple[str, str]:
    """Preserve 'Authorization: Bearer ' or 'Bearer ' prefix, anonymize the token."""
    token = match.group(1)
    full = match.group(0)
    prefix = full[: full.index(token)]
    return token, prefix


def _hex_secret_transform(match: re.Match) -> tuple[str, str]:
    """Preserve the key name prefix, anonymize the hex value."""
    prefix = match.group(1)
    value = match.group(2)
    return value, prefix


def _hex_secret_validator(match: re.Match) -> bool:
    """Skip already-redacted values."""
    return not match.group(2).startswith("REDACTED_")


def _ssh_key_transform(match: re.Match) -> tuple[str, str]:
    """Preserve key type prefix (ssh-rsa, etc.), anonymize the key data."""
    key_type = match.group(1)
    key_data = match.group(2)
    return key_data, f"{key_type} "


register(
    # Connection strings (must come before generic patterns)
    PatternHandler(
        name="connection_string",
        category="secret",
        regex=re.compile(
            r"(mysql|postgres|postgresql|mongodb|mongodb\+srv|redis|amqp)://"
            r"[^\s\"'`\]}>)]+",
            re.IGNORECASE,
        ),
        pseudonym_fn=_connection_string_pseudonym,
        priority=10,
    ),

    # Hex secrets (32-64 char hex in key/secret context)
    PatternHandler(
        name="hex_secret",
        category="secret",
        regex=re.compile(
            r"((?:webhook_secret|signing_secret|secret_key|hmac_key|"
            r"encryption_key|hash_key)\s*[=:]\s*[\"']?)"
            r"([a-fA-F0-9]{32,64})"
            r"(?=[\"'\s,;}\])#]|$)",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"REDACTED_HEX_{n}",
        priority=11,
        match_transform=_hex_secret_transform,
        validator=_hex_secret_validator,
    ),

    # JWT tokens
    PatternHandler(
        name="jwt",
        category="secret",
        regex=re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        pseudonym_fn=lambda n: f"REDACTED_JWT_{n}",
        priority=12,
    ),

    # Bearer tokens
    PatternHandler(
        name="bearer_token",
        category="secret",
        regex=re.compile(
            r"(?:Authorization:\s*)?Bearer\s+([a-zA-Z0-9._\-+/=]{20,})",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"REDACTED_BEARER_{n}",
        priority=13,
        match_transform=_bearer_transform,
    ),

    # SSH public keys
    PatternHandler(
        name="ssh_public_key",
        category="secret",
        regex=re.compile(
            r"(ssh-(?:rsa|ed25519|ecdsa|dsa))\s+(AAAA[0-9A-Za-z+/]+={0,2})"
        ),
        pseudonym_fn=lambda n: f"REDACTED_SSH_KEY_{n}",
        priority=13,
        match_transform=_ssh_key_transform,
    ),

    # PEM/PGP armored blocks. Backreference ties BEGIN/END labels together so
    # this covers RSA/EC/OPENSSH private keys *and* PGP PRIVATE KEY BLOCK /
    # PUBLIC KEY BLOCK / MESSAGE / SIGNATURE, which don't end in "KEY-----".
    PatternHandler(
        name="pem_key",
        category="secret",
        regex=re.compile(
            r"-----BEGIN([A-Z ]+)-----[\s\S]*?-----END\1-----"
        ),
        pseudonym_fn=lambda n: f"REDACTED_PEM_KEY_{n}",
        priority=14,
    ),

    # Specific API key formats (with or without quotes)
    PatternHandler(
        name="api_key",
        category="secret",
        regex=re.compile(
            r"\b(?:"
            r"(?:AKIA[0-9A-Z]{16})"                        # AWS access key
            r"|(?:sk-ant-[a-zA-Z0-9\-_]{20,})"             # Anthropic key
            r"|(?:sk-proj-[a-zA-Z0-9\-_]{20,})"            # OpenAI project key
            r"|(?:sk-[a-zA-Z0-9\-_]{20,})"                 # OpenAI key
            r"|(?:AIza[a-zA-Z0-9\-_]{20,})"                # Google key
            r"|(?:gsk_[a-zA-Z0-9]{20,})"                   # Groq key
            r"|(?:gh[pousr]_[A-Za-z0-9_]{36,})"            # GitHub token
            r"|(?:xox[baprs]-[0-9\-a-zA-Z]{20,})"          # Slack token
            r"|(?:hf_[a-zA-Z0-9]{20,})"                    # Hugging Face token
            r")\b",
        ),
        pseudonym_fn=lambda n: f"REDACTED_SECRET_{n}",
        priority=15,
    ),

    # Sentry DSN: embeds a project API key directly in a URL, near-universal
    # in any error-tracking config someone would paste for debugging.
    PatternHandler(
        name="sentry_dsn",
        category="secret",
        regex=re.compile(
            r"https://[a-f0-9]{32}@(?:o\d+\.)?ingest(?:\.[a-z]{2})?\.sentry\.io/\d+"
        ),
        pseudonym_fn=lambda n: f"https://REDACTED_SENTRY_DSN_{n}@ingest.sentry.io/0",
        priority=15,
    ),

    # Generic secret values: password/secret/token/key = "value" (quoted)
    PatternHandler(
        name="generic_secret",
        category="secret",
        regex=re.compile(
            r"((?:password|passwd|pwd|pass|passphrase|passkey|secret|secret_key|secretkey|"
            r"api_key|apikey|api_secret|apisecret|api_token|apitoken|token|auth_token|authtoken|"
            r"access_token|accesstoken|refresh_token|refreshtoken|bearer_token|session_token|"
            r"sessiontoken|access_key|accesskey|access_key_id|secret_access_key|private_key|"
            r"privatekey|public_key|publickey|client_secret|clientsecret|client_id|clientid|"
            r"client_key|app_secret|appsecret|app_key|appkey|consumer_key|consumer_secret|"
            r"signing_key|signing_secret|encryption_key|encryptionkey|decrypt_key|master_key|"
            r"masterkey|master_secret|master_password|root_password|admin_password|admin_key|"
            r"db_password|db_pass|database_password|database_pass|mysql_password|mysql_pwd|"
            r"postgres_password|pgpassword|mongo_password|redis_password|redis_auth|auth_key|"
            r"authkey|auth_secret|webhook_secret|webhook_key|hmac_key|hmac_secret|jwt_secret|"
            r"jwt_key|session_secret|cookie_secret|csrf_secret|csrf_token|xsrf_token|"
            r"oauth_token|oauth_secret|oauth_key|ssh_key|ssh_passphrase|gpg_passphrase|"
            r"ssl_password|tls_password|keystore_password|truststore_password|cert_password|"
            r"certificate_password|pfx_password|p12_password|smtp_password|ftp_password|"
            r"proxy_password|vpn_password|wifi_password|login_password|user_password|"
            r"account_password|credentials|creds|credential|service_key|service_account_key|"
            r"deploy_key|deploy_token|ci_token|npm_token|nuget_key|pypi_token|docker_password|"
            r"registry_password|vault_token|consul_token|nomad_token|encryption_password|"
            r"decryption_key|pin|pincode|pin_code|security_code|verification_code|otp|"
            r"one_time_password|mfa_secret|totp_secret|2fa_secret|recovery_key|backup_key|"
            r"license_key|licensekey|licence_key|activation_key|product_key|serial_key|"
            r"registration_key)"
            r"\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|is set to|is set as|set to|set as|equals)\s*[\"'])"
            r"([^\"']{4,})"
            r"(?=[\"'])",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"REDACTED_SECRET_{n}",
        priority=40,
        match_transform=_secret_value_transform,
        validator=_secret_value_validator,
    ),
    # Generic secret values: password/secret/token/key = value (unquoted)
    PatternHandler(
        name="generic_secret_unquoted",
        category="secret",
        regex=re.compile(
            r"((?:password|passwd|pwd|pass|passphrase|passkey|secret|secret_key|secretkey|"
            r"api_key|apikey|api_secret|apisecret|api_token|apitoken|token|auth_token|authtoken|"
            r"access_token|accesstoken|refresh_token|refreshtoken|bearer_token|session_token|"
            r"sessiontoken|access_key|accesskey|access_key_id|secret_access_key|private_key|"
            r"privatekey|public_key|publickey|client_secret|clientsecret|client_id|clientid|"
            r"client_key|app_secret|appsecret|app_key|appkey|consumer_key|consumer_secret|"
            r"signing_key|signing_secret|encryption_key|encryptionkey|decrypt_key|master_key|"
            r"masterkey|master_secret|master_password|root_password|admin_password|admin_key|"
            r"db_password|db_pass|database_password|database_pass|mysql_password|mysql_pwd|"
            r"postgres_password|pgpassword|mongo_password|redis_password|redis_auth|auth_key|"
            r"authkey|auth_secret|webhook_secret|webhook_key|hmac_key|hmac_secret|jwt_secret|"
            r"jwt_key|session_secret|cookie_secret|csrf_secret|csrf_token|xsrf_token|"
            r"oauth_token|oauth_secret|oauth_key|ssh_key|ssh_passphrase|gpg_passphrase|"
            r"ssl_password|tls_password|keystore_password|truststore_password|cert_password|"
            r"certificate_password|pfx_password|p12_password|smtp_password|ftp_password|"
            r"proxy_password|vpn_password|wifi_password|login_password|user_password|"
            r"account_password|credentials|creds|credential|service_key|service_account_key|"
            r"deploy_key|deploy_token|ci_token|npm_token|nuget_key|pypi_token|docker_password|"
            r"registry_password|vault_token|consul_token|nomad_token|encryption_password|"
            r"decryption_key|pin|pincode|pin_code|security_code|verification_code|otp|"
            r"one_time_password|mfa_secret|totp_secret|2fa_secret|recovery_key|backup_key|"
            r"license_key|licensekey|licence_key|activation_key|product_key|serial_key|"
            r"registration_key)"
            r"\s*(?:[=:]|is|are|was|were|will be|would be|should be|shall be|is set to|is set as|set to|set as|equals)\s*)"
            r"([^\s\"']{4,})",
            re.IGNORECASE,
        ),
        pseudonym_fn=lambda n: f"REDACTED_SECRET_{n}",
        priority=39,
        match_transform=_secret_value_transform,
        validator=_secret_value_validator,
    ),
)
