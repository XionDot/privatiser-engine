"""Tests for secret patterns: API keys, connection strings, JWT, PEM, generic secrets."""


class TestAPIKeys:
    def test_aws_access_key(self, p):
        text = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
        result, mapping = p.anonymize(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED_SECRET_" in result

    def test_openai_key(self, p):
        text = 'key = "sk-proj-FAKEabcdefghijklmnopqrstuvwxyzTESTVALUE"'
        result, mapping = p.anonymize(text)
        assert "sk-proj-" not in result
        assert "REDACTED_SECRET_" in result

    def test_anthropic_key(self, p):
        text = 'key = "sk-ant-FAKEabcdefghijklmnopqrstuvwxyzTESTVALUE"'
        result, _ = p.anonymize(text)
        assert "sk-ant-" not in result

    def test_github_token(self, p):
        text = 'token = "ghp_FAKEABCDEFGHIJKLMNOPQRSTUVWXYZTESTVALUE"'
        result, _ = p.anonymize(text)
        assert "ghp_" not in result

    def test_slack_token(self, p):
        text = 'token = "xoxb-FAKE1234567890-TESTVALUEabcdefghijklmnop"'
        result, _ = p.anonymize(text)
        assert "xoxb-" not in result


class TestConnectionStrings:
    def test_postgresql(self, p):
        text = 'db = "postgresql://admin:pass@db.myhost.com:5432/mydb"'
        result, mapping = p.anonymize(text)
        assert "admin:pass" not in result
        assert "myhost.com" not in result
        assert "REDACTED_CONNSTR_" in result

    def test_mysql(self, p):
        text = 'db = "mysql://root:secret@localhost:3306/app"'
        result, _ = p.anonymize(text)
        assert "root:secret" not in result
        assert "REDACTED_CONNSTR_" in result

    def test_redis(self, p):
        text = 'cache = "redis://user:pass@redis.internal.com:6379/0"'
        result, _ = p.anonymize(text)
        assert "user:pass" not in result
        assert "REDACTED_CONNSTR_" in result


class TestGenericSecrets:
    def test_password_equals(self, p):
        text = 'password = "my-super-secret"'
        result, mapping = p.anonymize(text)
        assert "my-super-secret" not in result
        assert "password" in result  # keyword preserved
        assert "REDACTED_SECRET_" in result

    def test_api_key_colon(self, p):
        text = "api_key: 'long-random-key-value-here'"
        result, _ = p.anonymize(text)
        assert "long-random-key-value-here" not in result

    def test_short_values_not_matched(self, p):
        # Values shorter than 4 chars should not be matched
        text = 'password = "abc"'
        result, mapping = p.anonymize(text)
        assert "abc" in result

    def test_already_redacted(self, p):
        text = 'password = "REDACTED_SECRET_1"'
        result, _ = p.anonymize(text)
        assert result == text


class TestGenericSecretGrammar:
    """Test natural language grammar forms for secret detection."""

    def test_password_is_quoted(self, p):
        text = 'password is "secret123"'
        result, mapping = p.anonymize(text)
        assert "secret123" not in result
        assert "REDACTED_SECRET_" in result

    def test_password_is_unquoted(self, p):
        text = "password is secret123"
        result, mapping = p.anonymize(text)
        assert "secret123" not in result
        assert "REDACTED_SECRET_" in result

    def test_credentials_are(self, p):
        text = 'credentials are "admin:pass1234"'
        result, mapping = p.anonymize(text)
        assert "admin:pass1234" not in result
        assert "REDACTED_SECRET_" in result

    def test_password_was(self, p):
        text = 'password was "oldpassword123"'
        result, mapping = p.anonymize(text)
        assert "oldpassword123" not in result

    def test_token_will_be(self, p):
        text = 'token will be "newtokenvalue123"'
        result, mapping = p.anonymize(text)
        assert "newtokenvalue123" not in result

    def test_secret_should_be(self, p):
        text = 'secret should be "rotated_value_xyz"'
        result, mapping = p.anonymize(text)
        assert "rotated_value_xyz" not in result

    def test_password_set_to(self, p):
        text = 'password set to "myNewP@ssw0rd"'
        result, mapping = p.anonymize(text)
        assert "myNewP@ssw0rd" not in result

    def test_api_key_equals(self, p):
        text = 'api_key equals "sk-1234567890abcdef"'
        result, mapping = p.anonymize(text)
        assert "sk-1234567890abcdef" not in result

    def test_unquoted_password_was(self, p):
        text = "password was supersecret123"
        result, mapping = p.anonymize(text)
        assert "supersecret123" not in result

    def test_unquoted_token_set_to(self, p):
        text = "token set to abc123xyz789"
        result, mapping = p.anonymize(text)
        assert "abc123xyz789" not in result

    def test_round_trip_grammar(self, p):
        text = 'password is "secret123"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestGenericSecretKeywords:
    """Test expanded keyword coverage."""

    def test_db_pass(self, p):
        text = 'db_pass = "mydbpassword"'
        result, _ = p.anonymize(text)
        assert "mydbpassword" not in result

    def test_mysql_password(self, p):
        text = 'mysql_password = "rootpass123"'
        result, _ = p.anonymize(text)
        assert "rootpass123" not in result

    def test_postgres_password(self, p):
        text = 'postgres_password = "pgpass456"'
        result, _ = p.anonymize(text)
        assert "pgpass456" not in result

    def test_redis_password(self, p):
        text = 'redis_password = "redisauth789"'
        result, _ = p.anonymize(text)
        assert "redisauth789" not in result

    def test_smtp_password(self, p):
        text = 'smtp_password = "mailpass123"'
        result, _ = p.anonymize(text)
        assert "mailpass123" not in result

    def test_client_secret(self, p):
        text = 'client_secret = "oauth-secret-value"'
        result, _ = p.anonymize(text)
        assert "oauth-secret-value" not in result

    def test_webhook_secret_keyword(self, p):
        text = 'webhook_secret = "whsec_abcdefg123"'
        result, _ = p.anonymize(text)
        assert "whsec_abcdefg123" not in result

    def test_jwt_secret(self, p):
        text = 'jwt_secret = "my-jwt-signing-key"'
        result, _ = p.anonymize(text)
        assert "my-jwt-signing-key" not in result

    def test_session_secret(self, p):
        text = 'session_secret = "sess_abc123xyz"'
        result, _ = p.anonymize(text)
        assert "sess_abc123xyz" not in result

    def test_encryption_key(self, p):
        text = 'encryption_key = "enc-key-value-here"'
        result, _ = p.anonymize(text)
        assert "enc-key-value-here" not in result

    def test_deploy_token(self, p):
        text = 'deploy_token = "gldt-abc123xyz456"'
        result, _ = p.anonymize(text)
        assert "gldt-abc123xyz456" not in result

    def test_vault_token(self, p):
        text = 'vault_token = "hvs.abcdefghijklmnop"'
        result, _ = p.anonymize(text)
        assert "hvs.abcdefghijklmnop" not in result

    def test_npm_token(self, p):
        text = 'npm_token = "npm_abcdefghij1234"'
        result, _ = p.anonymize(text)
        assert "npm_abcdefghij1234" not in result

    def test_mfa_secret(self, p):
        text = 'mfa_secret = "JBSWY3DPEHPK3PXP"'
        result, _ = p.anonymize(text)
        assert "JBSWY3DPEHPK3PXP" not in result

    def test_license_key(self, p):
        text = 'license_key = "XXXX-YYYY-ZZZZ-1234"'
        result, _ = p.anonymize(text)
        assert "XXXX-YYYY-ZZZZ-1234" not in result

    def test_passphrase(self, p):
        text = 'passphrase = "correct horse battery staple"'
        result, _ = p.anonymize(text)
        assert "correct horse battery staple" not in result

    def test_refresh_token(self, p):
        text = 'refresh_token = "1//abcdefghijklmnop"'
        result, _ = p.anonymize(text)
        assert "1//abcdefghijklmnop" not in result

    def test_consumer_secret(self, p):
        text = 'consumer_secret = "twitter-consumer-secret"'
        result, _ = p.anonymize(text)
        assert "twitter-consumer-secret" not in result

    def test_docker_password(self, p):
        text = 'docker_password = "dckr_pat_abc123"'
        result, _ = p.anonymize(text)
        assert "dckr_pat_abc123" not in result


class TestJWT:
    def test_jwt_token(self, p):
        # A plausible JWT structure (header.payload.signature)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789"
        text = f'token = "{jwt}"'
        result, mapping = p.anonymize(text)
        assert "eyJ" not in result
        assert "REDACTED_JWT_" in result


class TestBearerTokens:
    def test_authorization_header(self, p):
        text = "Authorization: Bearer abc123xyz789def456ghi012jkl345"
        result, mapping = p.anonymize(text)
        assert "abc123xyz789" not in result
        assert "Bearer" in result
        assert "REDACTED_BEARER_" in result

    def test_standalone_bearer(self, p):
        text = "Bearer abcdefghijklmnopqrstuvwxyz1234567890"
        result, _ = p.anonymize(text)
        assert "abcdefghijklmnopqrstuvwxyz" not in result
        assert "Bearer " in result

    def test_round_trip(self, p):
        text = "Authorization: Bearer abc123xyz789def456ghi012jkl345"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestHexSecrets:
    def test_webhook_secret(self, p):
        hex_val = "a1b2c3d4e5f67890abcdef1234567890"
        text = f'webhook_secret = "{hex_val}"'
        result, mapping = p.anonymize(text)
        assert hex_val not in result
        assert "REDACTED_HEX_" in result
        assert "webhook_secret" in result

    def test_signing_secret(self, p):
        hex_val = "ff" * 32
        text = f"signing_secret: {hex_val}"
        result, _ = p.anonymize(text)
        assert hex_val not in result

    def test_round_trip(self, p):
        hex_val = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        text = f'webhook_secret = "{hex_val}"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestSSHKeys:
    def test_ssh_rsa(self, p):
        text = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example user@host"
        result, mapping = p.anonymize(text)
        assert "AAAAB3NzaC1yc2E" not in result
        assert "ssh-rsa" in result
        assert "REDACTED_SSH_KEY_" in result

    def test_ssh_ed25519(self, p):
        text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey user@host"
        result, _ = p.anonymize(text)
        assert "AAAAC3NzaC1lZDI1NTE5" not in result
        assert "ssh-ed25519" in result

    def test_round_trip(self, p):
        text = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7example user@host"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestPEMKey:
    def test_rsa_private_key(self, p):
        text = '-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...base64...\n-----END RSA PRIVATE KEY-----'
        result, _ = p.anonymize(text)
        assert "MIIBogIBAAJ" not in result
        assert "REDACTED_PEM_KEY_" in result
