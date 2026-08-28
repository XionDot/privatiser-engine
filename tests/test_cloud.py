"""Tests for cloud provider patterns (Azure, GCP)."""

import pytest
from privatiser import Privatiser


@pytest.fixture
def p():
    return Privatiser()


class TestAzureSubscription:
    def test_subscription_in_resource_id(self, p):
        text = "/subscriptions/12345678-1234-1234-1234-123456789abc/resourceGroups/rg"
        result, mapping = p.anonymize(text)
        assert "12345678-1234" not in result
        assert "/subscriptions/" in result
        assert len(mapping) == 1

    def test_round_trip(self, p):
        text = "/subscriptions/abcdef01-2345-6789-abcd-ef0123456789/providers/Microsoft.Compute"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestGCPProject:
    def test_project_in_path(self, p):
        text = "projects/my-production-project/instances/db-main"
        result, mapping = p.anonymize(text)
        assert "my-production-project" not in result
        assert "projects/" in result
        assert "redacted-project" in result

    def test_round_trip(self, p):
        text = "projects/my-staging-environment/zones/us-central1-a"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestCategoryToggle:
    def test_disable_cloud(self):
        p = Privatiser(enabled_categories={"cloud": False})
        text = "projects/my-production-project/instances/db"
        result, mapping = p.anonymize(text)
        assert "my-production-project" in result  # Not anonymized by cloud handler

    def test_disable_secrets(self):
        p = Privatiser(enabled_categories={"secrets": False})
        text = 'password = "secret123"'
        result, mapping = p.anonymize(text)
        assert "secret123" in result

    def test_disable_network(self):
        p = Privatiser(enabled_categories={"network": False})
        text = "server at 192.168.1.100"
        result, mapping = p.anonymize(text)
        assert "192.168.1.100" in result

    def test_other_categories_still_work(self):
        p = Privatiser(enabled_categories={"pii": False})
        text = "IP 192.168.1.1 and SSN 123-45-6789"
        result, mapping = p.anonymize(text)
        assert "192.168.1.1" not in result  # IP still anonymized
        assert "123-45-6789" in result  # SSN not anonymized


class TestAllowlist:
    def test_allowlist_ip(self):
        p = Privatiser(allowlist=["192.168.1.100"])
        text = "servers: 192.168.1.100 and 10.0.0.50"
        result, mapping = p.anonymize(text)
        assert "192.168.1.100" in result  # Allowlisted
        assert "10.0.0.50" not in result  # Still anonymized

    def test_allowlist_email(self):
        p = Privatiser(allowlist=["admin@example.org"])
        text = "contact admin@example.org or user@company.com"
        result, mapping = p.anonymize(text)
        assert "admin@example.org" in result
        assert "user@company.com" not in result

    def test_allowlist_exact_match_only(self):
        """Allowlist uses exact match - a domain entry does NOT protect emails at that domain."""
        p = Privatiser(allowlist=["admin@example.org"])
        text = "contact admin@example.org"
        result, mapping = p.anonymize(text)
        assert "admin@example.org" in result
