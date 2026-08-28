"""Tests for CLI commands."""

import json
import os
import tempfile

from click.testing import CliRunner

from privatiser.cli import main


class TestAnonymize:
    def test_stdin(self):
        runner = CliRunner()
        result = runner.invoke(main, ["anonymize"], input='password = "mysecret123"\n')
        assert result.exit_code == 0
        assert "mysecret123" not in result.output
        assert "REDACTED_SECRET_" in result.output

    def test_file_input(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("input.txt", "w") as f:
                f.write('server = "192.168.1.100"\n')
            result = runner.invoke(main, ["anonymize", "input.txt"])
            assert result.exit_code == 0
            assert "192.168.1.100" not in result.output
            assert "10." in result.output

    def test_output_file(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("input.txt", "w") as f:
                f.write('ip = "192.168.1.1"\n')
            result = runner.invoke(main, ["anonymize", "input.txt", "-o", "output.txt"])
            assert result.exit_code == 0
            with open("output.txt") as f:
                content = f.read()
            assert "192.168.1.1" not in content

    def test_mapping_file(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("input.txt", "w") as f:
                f.write('ip = "192.168.1.1"\n')
            result = runner.invoke(main, ["anonymize", "input.txt", "-m", "mapping.json"])
            assert result.exit_code == 0
            assert os.path.exists("mapping.json")
            with open("mapping.json") as f:
                mapping = json.load(f)
            assert len(mapping) >= 1
            assert "192.168.1.1" in mapping.values()


class TestDeanonymize:
    def test_round_trip(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            original = 'server = "192.168.1.100"\npassword = "secret123!"\n'
            with open("input.txt", "w") as f:
                f.write(original)

            # Anonymize
            runner.invoke(main, ["anonymize", "input.txt", "-o", "anon.txt", "-m", "mapping.json"])

            # Deanonymize
            result = runner.invoke(main, ["deanonymize", "anon.txt", "-m", "mapping.json"])
            assert result.exit_code == 0
            assert "192.168.1.100" in result.output
            assert "secret123!" in result.output

    def test_missing_mapping(self):
        runner = CliRunner()
        result = runner.invoke(main, ["deanonymize", "-m", "nonexistent.json"], input="text")
        assert result.exit_code != 0


class TestDisableCategories:
    def test_disable_pii(self):
        runner = CliRunner()
        result = runner.invoke(main, ["anonymize", "-d", "pii"], input="SSN: 123-45-6789\nIP: 192.168.1.1\n")
        assert result.exit_code == 0
        assert "123-45-6789" in result.output  # PII disabled
        assert "192.168.1.1" not in result.output  # Network still active

    def test_disable_network(self):
        runner = CliRunner()
        result = runner.invoke(main, ["anonymize", "-d", "network"], input="server at 192.168.1.100\n")
        assert result.exit_code == 0
        assert "192.168.1.100" in result.output

    def test_disable_multiple(self):
        runner = CliRunner()
        result = runner.invoke(
            main, ["anonymize", "-d", "pii", "-d", "network"],
            input="IP: 192.168.1.1 SSN: 123-45-6789\n"
        )
        assert result.exit_code == 0
        assert "192.168.1.1" in result.output
        assert "123-45-6789" in result.output


class TestAllowlistFile:
    def test_allowlist_skip(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("allow.txt", "w") as f:
                f.write("192.168.1.100\n")
            result = runner.invoke(
                main, ["anonymize", "--allowlist", "allow.txt"],
                input="servers: 192.168.1.100 and 10.0.0.50\n"
            )
            assert result.exit_code == 0
            assert "192.168.1.100" in result.output  # Allowlisted
            assert "10.0.0.50" not in result.output  # Still anonymized


class TestEnvMode:
    def test_env_basic(self):
        runner = CliRunner()
        env_content = 'DB_HOST=192.168.1.100\nDB_PASSWORD="supersecret123"\n# comment\nAPP_NAME=myapp\n'
        result = runner.invoke(main, ["anonymize", "--env"], input=env_content)
        assert result.exit_code == 0
        assert "DB_HOST=" in result.output
        assert "DB_PASSWORD=" in result.output
        assert "192.168.1.100" not in result.output
        assert "supersecret123" not in result.output  # Key-based secret detection
        assert "REDACTED_ENV_" in result.output
        assert "# comment" in result.output
        assert "APP_NAME=myapp" in result.output  # No sensitive data, unchanged

    def test_env_pattern_values(self):
        """Values that match patterns (IPs, API keys) are anonymized regardless of key name."""
        runner = CliRunner()
        env_content = 'MY_IP=192.168.1.100\nANTHROPIC_KEY="sk-ant-FAKEabcdeTESTVALUEqrstu"\n'
        result = runner.invoke(main, ["anonymize", "--env"], input=env_content)
        assert result.exit_code == 0
        assert "192.168.1.100" not in result.output
        assert "sk-ant-" not in result.output

    def test_env_secret_key_names(self):
        """Keys containing password/secret/token/key/auth/credential get values redacted."""
        runner = CliRunner()
        env_content = (
            'DB_PASSWORD=mysecretpwd\n'
            'AUTH_TOKEN=some-random-token\n'
            'PRIVATE_KEY=mykey123\n'
            'MY_CREDENTIAL=cred-abc\n'
            'APP_NAME=myapp\n'
        )
        result = runner.invoke(main, ["anonymize", "--env"], input=env_content)
        assert result.exit_code == 0
        assert "mysecretpwd" not in result.output
        assert "some-random-token" not in result.output
        assert "mykey123" not in result.output
        assert "cred-abc" not in result.output
        assert "APP_NAME=myapp" in result.output  # Non-secret key, untouched

    def test_env_preserves_quotes(self):
        runner = CliRunner()
        result = runner.invoke(main, ["anonymize", "--env"], input='SECRET="sk-ant-FAKEabcdeTESTVALUEqrst"\n')
        assert result.exit_code == 0
        assert "sk-ant-" not in result.output
        assert 'SECRET="' in result.output  # Key and opening quote preserved

    def test_env_round_trip(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            env_content = 'API_KEY="sk-ant-FAKEabcdeTESTVALUEqrstu"\nDB_HOST=10.20.30.40\n'
            with open(".env", "w") as f:
                f.write(env_content)
            runner.invoke(main, ["anonymize", ".env", "--env", "-o", "anon.env", "-m", "mapping.json"])
            result = runner.invoke(main, ["deanonymize", "anon.env", "-m", "mapping.json"])
            assert result.exit_code == 0
            assert "sk-ant-FAKEabcdeTESTVALUEqrstu" in result.output
            assert "10.20.30.40" in result.output

    def test_env_secret_round_trip(self):
        """Key-based secret detection should also be reversible."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            env_content = 'DB_PASSWORD=supersecret123\nAPP_NAME=myapp\n'
            with open(".env", "w") as f:
                f.write(env_content)
            runner.invoke(main, ["anonymize", ".env", "--env", "-o", "anon.env", "-m", "mapping.json"])
            result = runner.invoke(main, ["deanonymize", "anon.env", "-m", "mapping.json"])
            assert result.exit_code == 0
            assert "supersecret123" in result.output
            assert "APP_NAME=myapp" in result.output
