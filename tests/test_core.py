"""Tests for core Privatiser functionality: round-trips, edge cases, integration."""

from privatiser import Privatiser


class TestRoundTrip:
    def test_anonymize_then_deanonymize(self, p, sample_config):
        anonymized, mapping = p.anonymize(sample_config)
        restored = p.deanonymize(anonymized, mapping)
        assert restored == sample_config

    def test_deanonymize_with_instance_mapping(self, p):
        text = 'server = "192.168.1.100"'
        anonymized, _ = p.anonymize(text)
        # Use the instance's internal mapping (no explicit mapping arg)
        restored = p.deanonymize(anonymized)
        assert restored == text


class TestConsistency:
    def test_same_value_same_pseudonym(self, p):
        text = "a = 192.168.1.1\nb = 192.168.1.1"
        result, mapping = p.anonymize(text)
        lines = result.strip().split("\n")
        assert lines[0].split("= ")[1] == lines[1].split("= ")[1]
        # Only one mapping entry
        assert len(mapping) == 1

    def test_different_values_different_pseudonyms(self, p):
        text = "a = 192.168.1.1\nb = 192.168.1.2"
        result, mapping = p.anonymize(text)
        assert len(mapping) == 2


class TestEdgeCases:
    def test_empty_input(self, p):
        result, mapping = p.anonymize("")
        assert result == ""
        assert mapping == {}

    def test_no_sensitive_data(self, p):
        text = "Hello, this is a normal sentence with no secrets."
        result, mapping = p.anonymize(text)
        assert result == text
        assert mapping == {}

    def test_whitespace_only(self, p):
        text = "   \n\t\n   "
        result, mapping = p.anonymize(text)
        assert result == text
        assert mapping == {}

    def test_deanonymize_empty(self, p):
        assert p.deanonymize("", {}) == ""
        assert p.deanonymize("", None) == ""

    def test_deanonymize_no_mapping(self, p):
        text = "nothing to restore"
        assert p.deanonymize(text, {}) == text


class TestDeanonymizeData:
    def test_dict(self, p):
        text = 'ip = "192.168.1.1"'
        _, mapping = p.anonymize(text)
        data = {"server": list(mapping.keys())[0], "port": 5432}
        restored = p.deanonymize_data(data, mapping)
        assert restored["server"] == "192.168.1.1"
        assert restored["port"] == 5432

    def test_nested_list(self, p):
        text = 'contact = "admin@mycompany.com"'
        _, mapping = p.anonymize(text)
        pseudonym = list(mapping.keys())[0]
        data = [{"emails": [pseudonym]}, "plain"]
        restored = p.deanonymize_data(data, mapping)
        assert restored[0]["emails"][0] == "admin@mycompany.com"
        assert restored[1] == "plain"


class TestReset:
    def test_reset_clears_state(self, p):
        p.anonymize('server = "192.168.1.1"')
        assert len(p.get_mapping()) > 0
        p.reset()
        assert len(p.get_mapping()) == 0


class TestExtraPatterns:
    def test_custom_pattern_via_constructor(self):
        from privatiser.patterns import PatternHandler
        import re

        custom = PatternHandler(
            name="order_id",
            category="order",
            regex=re.compile(r"ORD-\d{8}"),
            pseudonym_fn=lambda n: f"ORD-REDACTED-{n}",
            priority=80,
        )
        p = Privatiser(extra_patterns=[custom])
        result, mapping = p.anonymize("order ORD-12345678 confirmed")
        assert "ORD-12345678" not in result
        assert "ORD-REDACTED-" in result


class TestIntegration:
    def test_mixed_content(self, p, sample_config):
        result, mapping = p.anonymize(sample_config)

        # Sensitive data should be gone
        assert "mycompany.com" not in result
        assert "SuperSecret123!" not in result
        assert "192.168.1.100" not in result
        assert "123456789012" not in result
        assert "my-prod-logs-bucket" not in result

        # Structure should be preserved
        assert "db_host" in result
        assert "db_port = 5432" in result
        assert "# Database config" in result
        assert "# AWS" in result

        # Should have multiple mappings
        assert len(mapping) >= 5
