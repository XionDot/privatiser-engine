"""Tests for network patterns: IP, domain, email, MAC address."""


class TestIPv4:
    def test_basic_ip(self, p):
        result, mapping = p.anonymize('server = "192.168.1.100"')
        assert "192.168.1.100" not in result
        assert "10." in result
        assert len(mapping) == 1

    def test_ip_with_cidr(self, p):
        result, mapping = p.anonymize("cidr = 10.0.0.0/16")
        assert "10.0.0.0" not in result
        assert "/16" in result

    def test_skip_localhost(self, p):
        result, _ = p.anonymize("bind = 127.0.0.1")
        assert "127.0.0.1" in result

    def test_skip_all_zeros(self, p):
        result, _ = p.anonymize("listen = 0.0.0.0")
        assert "0.0.0.0" in result

    def test_skip_broadcast(self, p):
        result, _ = p.anonymize("broadcast = 255.255.255.255")
        assert "255.255.255.255" in result

    def test_consistency(self, p):
        text = "a = 192.168.1.1\nb = 192.168.1.1\nc = 192.168.1.2"
        result, mapping = p.anonymize(text)
        lines = result.strip().split("\n")
        # Same IP gets same pseudonym
        ip1 = lines[0].split("= ")[1]
        ip2 = lines[1].split("= ")[1]
        assert ip1 == ip2
        # Different IP gets different pseudonym
        ip3 = lines[2].split("= ")[1]
        assert ip1 != ip3

    def test_multiple_ips_in_one_line(self, p):
        result, mapping = p.anonymize("from 192.168.1.1 to 10.20.30.40")
        assert "192.168.1.1" not in result
        assert "10.20.30.40" not in result
        assert len(mapping) == 2


class TestDomain:
    def test_basic_domain(self, p):
        result, mapping = p.anonymize("host = prod-db.mycompany.com")
        assert "mycompany.com" not in result
        assert "redacted-host" in result

    def test_skip_cloud_domains(self, p):
        result, _ = p.anonymize("endpoint = s3.amazonaws.com")
        assert "amazonaws.com" in result

    def test_skip_github(self, p):
        result, _ = p.anonymize("repo = github.com")
        assert "github.com" in result

    def test_subdomain(self, p):
        result, mapping = p.anonymize("api.staging.mycompany.io")
        assert "mycompany" not in result
        assert len(mapping) >= 1


class TestEmail:
    def test_basic_email(self, p):
        result, mapping = p.anonymize("contact = admin@mycompany.com")
        assert "admin@mycompany.com" not in result
        assert "user-" in result
        assert "@redacted.example.net" in result

    def test_email_with_dots(self, p):
        result, _ = p.anonymize("john.doe.jr@example-corp.org")
        assert "john.doe" not in result

    def test_multiple_emails(self, p):
        text = "to: a@test.com, cc: b@test.com"
        result, mapping = p.anonymize(text)
        assert "a@test.com" not in result
        assert "b@test.com" not in result
        assert len(mapping) >= 2


class TestPrivateURLs:
    def test_url_with_port(self, p):
        text = "endpoint = http://internal-api.company.com:8080/v1/users"
        result, mapping = p.anonymize(text)
        assert "internal-api.company.com:8080" not in result
        assert "redacted-internal" in result

    def test_https_staging(self, p):
        text = "https://staging.myapp.io:3000/admin"
        result, _ = p.anonymize(text)
        assert "staging.myapp.io:3000" not in result

    def test_round_trip(self, p):
        text = "http://dev-server.local:9200/api"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text


class TestMACAddress:
    def test_colon_format(self, p):
        result, mapping = p.anonymize("mac = AA:BB:CC:DD:EE:FF")
        assert "DD:EE:FF" not in result
        assert len(mapping) == 1

    def test_dash_format(self, p):
        result, mapping = p.anonymize("mac = AA-BB-CC-DD-EE-FF")
        assert "DD-EE-FF" not in result

    def test_lowercase(self, p):
        result, mapping = p.anonymize("mac = aa:bb:cc:dd:ee:ff")
        assert "dd:ee:ff" not in result
