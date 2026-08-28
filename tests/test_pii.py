"""Tests for PII patterns: phone numbers, credit cards, SSN, passport, IBAN."""


class TestUSPhone:
    def test_formatted_phone(self, p):
        result, mapping = p.anonymize("call (555) 123-4567")
        assert "123-4567" not in result
        assert "(555) 000-" in result

    def test_dashed_phone(self, p):
        result, _ = p.anonymize("phone: 555-123-4567")
        assert "123-4567" not in result

    def test_dotted_phone(self, p):
        result, _ = p.anonymize("phone: 555.123.4567")
        assert "123.4567" not in result

    def test_with_country_code(self, p):
        result, _ = p.anonymize("phone: +1-555-123-4567")
        assert "123-4567" not in result

    def test_bare_digits_not_matched(self, p):
        # 10 digits without any formatting should NOT match (avoids false positives)
        result, mapping = p.anonymize("id = 5551234567")
        assert "5551234567" in result


class TestUKPhone:
    def test_uk_mobile(self, p):
        result, _ = p.anonymize("phone: +44 7911 123456")
        assert "7911 123456" not in result
        assert "+44 7700" in result


class TestCreditCard:
    def test_visa(self, p):
        # 4111111111111111 passes Luhn
        result, mapping = p.anonymize("card: 4111 1111 1111 1111")
        assert "4111" not in result
        assert "4000-0000-0000-" in result

    def test_invalid_luhn_not_matched(self, p):
        # Random 16-digit number that fails Luhn
        result, _ = p.anonymize("ref: 1234 5678 9012 3456")
        # Should not be anonymized (fails Luhn)
        assert "1234" in result

    def test_dashed_card(self, p):
        result, _ = p.anonymize("card: 4111-1111-1111-1111")
        assert "4111" not in result


class TestSSN:
    def test_valid_ssn(self, p):
        result, mapping = p.anonymize("ssn: 123-45-6789")
        assert "123-45-6789" not in result
        assert "078-05-" in result

    def test_invalid_area_000(self, p):
        result, _ = p.anonymize("ssn: 000-45-6789")
        assert "000-45-6789" in result  # should not be anonymized

    def test_invalid_area_666(self, p):
        result, _ = p.anonymize("ssn: 666-45-6789")
        assert "666-45-6789" in result

    def test_invalid_area_900(self, p):
        result, _ = p.anonymize("ssn: 900-45-6789")
        assert "900-45-6789" in result


class TestPassport:
    def test_us_passport(self, p):
        result, mapping = p.anonymize("passport: C12345678")
        assert "C12345678" not in result
        assert "X0000" in result


class TestIBAN:
    def test_german_iban(self, p):
        result, mapping = p.anonymize("iban: DE89370400440532013000")
        assert "DE89370400440532013000" not in result
        assert "GB00XXXX" in result

    def test_uk_iban(self, p):
        result, _ = p.anonymize("iban: GB29NWBK60161331926819")
        assert "GB29NWBK" not in result
