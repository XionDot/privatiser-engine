"""Tests for international patterns: phones, IDs, postcodes, dates, i18n secrets."""

from privatiser import Privatiser


class TestInternationalPhones:
    def test_french_phone(self):
        p = Privatiser()
        text = "call +33 6 12 34 56 78"
        result, mapping = p.anonymize(text)
        assert "+33 6 12 34 56 78" not in result
        assert len(mapping) >= 1

    def test_french_phone_local(self):
        p = Privatiser()
        text = "call 06 12 34 56 78"
        result, mapping = p.anonymize(text)
        assert "06 12 34 56 78" not in result

    def test_german_phone(self):
        p = Privatiser()
        text = "call +49 30 1234567"
        result, mapping = p.anonymize(text)
        assert "+49 30 1234567" not in result

    def test_spanish_phone(self):
        p = Privatiser()
        text = "call +34 612 345 678"
        result, mapping = p.anonymize(text)
        assert "+34 612 345 678" not in result

    def test_italian_phone(self):
        p = Privatiser()
        text = "call +39 312 345 6789"
        result, mapping = p.anonymize(text)
        assert "+39 312 345 6789" not in result

    def test_brazilian_phone(self):
        p = Privatiser()
        text = "call +55 11 91234 5678"
        result, mapping = p.anonymize(text)
        assert "+55 11 91234 5678" not in result

    def test_indian_phone(self):
        p = Privatiser()
        text = "call +91 9876543210"
        result, mapping = p.anonymize(text)
        assert "9876543210" not in result

    def test_australian_phone(self):
        p = Privatiser()
        text = "call +61 412 345 678"
        result, mapping = p.anonymize(text)
        assert "+61 412 345 678" not in result

    def test_japanese_phone(self):
        p = Privatiser()
        text = "call +81 90 1234 5678"
        result, mapping = p.anonymize(text)
        assert "+81 90 1234 5678" not in result


class TestNationalIDs:
    def test_french_insee(self):
        p = Privatiser()
        text = "INSEE: 1 85 12 75 123 456 78"
        result, mapping = p.anonymize(text)
        assert "85 12 75 123 456 78" not in result

    def test_indian_aadhaar(self):
        p = Privatiser()
        text = "Aadhaar: 2345 6789 0123"
        result, mapping = p.anonymize(text)
        assert "2345 6789 0123" not in result

    def test_indian_aadhaar_no_false_positive(self):
        p = Privatiser()
        text = "id: 550e8400-e29b-41d4-a716-446655440000"
        result, mapping = p.anonymize(text)
        # Aadhaar should NOT match inside a UUID
        assert "2000 0000" not in result

    def test_indian_pan(self):
        p = Privatiser()
        text = "PAN: ABCDE1234F"
        result, mapping = p.anonymize(text)
        assert "ABCDE1234F" not in result

    def test_canadian_sin(self):
        p = Privatiser()
        text = "SIN: 123-456-789"
        result, mapping = p.anonymize(text)
        assert "123-456-789" not in result

    def test_australian_tfn(self):
        p = Privatiser()
        text = "TFN: 123 456 789"
        result, mapping = p.anonymize(text)
        assert "123 456 789" not in result


class TestPostcodes:
    def test_uk_postcode(self):
        p = Privatiser()
        text = "address: SW1A 1AA"
        result, mapping = p.anonymize(text)
        assert "SW1A 1AA" not in result

    def test_japanese_postcode(self):
        p = Privatiser()
        text = "address: 〒100-0001"
        result, mapping = p.anonymize(text)
        assert "100-0001" not in result

    def test_canadian_postcode(self):
        p = Privatiser()
        text = "address: K1A 0B1"
        result, mapping = p.anonymize(text)
        assert "K1A 0B1" not in result

    def test_german_postcode_with_context(self):
        p = Privatiser()
        text = "PLZ: 10115"
        result, mapping = p.anonymize(text)
        assert "10115" not in result

    def test_french_postcode_with_context(self):
        p = Privatiser()
        text = "code postal: 75001"
        result, mapping = p.anonymize(text)
        assert "75001" not in result

    def test_indian_pincode_with_context(self):
        p = Privatiser()
        text = "PIN code: 110001"
        result, mapping = p.anonymize(text)
        assert "110001" not in result


class TestDateFormats:
    def test_eu_date_slash(self):
        p = Privatiser()
        text = "born on 15/03/1990"
        result, mapping = p.anonymize(text)
        assert "15/03/1990" not in result

    def test_eu_date_dot(self):
        p = Privatiser()
        text = "born on 15.03.1990"
        result, mapping = p.anonymize(text)
        assert "15.03.1990" not in result

    def test_iso_date(self):
        p = Privatiser()
        text = "date: 2024-03-15"
        result, mapping = p.anonymize(text)
        assert "2024-03-15" not in result

    def test_iso_date_slash(self):
        p = Privatiser()
        text = "date: 2024/03/15"
        result, mapping = p.anonymize(text)
        assert "2024/03/15" not in result


class TestI18nSecrets:
    def test_french_password_quoted(self):
        p = Privatiser()
        text = 'le mot_de_passe est dans la config avec mot_de_passe = "hunter2"'
        result, mapping = p.anonymize(text)
        assert "hunter2" not in result

    def test_french_api_key(self):
        p = Privatiser()
        text = 'la cle_api est dans la config: cle_api = "abc123xyz"'
        result, mapping = p.anonymize(text)
        assert "abc123xyz" not in result

    def test_spanish_password(self):
        p = Privatiser()
        text = 'el servidor con la contraseña para contraseña = "secreto123"'
        result, mapping = p.anonymize(text)
        assert "secreto123" not in result

    def test_german_password(self):
        p = Privatiser()
        text = 'der Server ist mit dem Passwort und passwort = "geheim123"'
        result, mapping = p.anonymize(text)
        assert "geheim123" not in result

    def test_portuguese_password(self):
        p = Privatiser()
        text = 'o servidor com a senha para o usuario: senha = "segredo123"'
        result, mapping = p.anonymize(text)
        assert "segredo123" not in result

    def test_dutch_password(self):
        p = Privatiser()
        text = 'de server met het wachtwoord voor wachtwoord = "geheim456"'
        result, mapping = p.anonymize(text)
        assert "geheim456" not in result

    def test_unquoted_i18n_secret(self):
        p = Privatiser()
        text = "le mot_de_passe est dans la config: mot_de_passe=hunter2secret"
        result, mapping = p.anonymize(text)
        assert "hunter2secret" not in result

    def test_chinese_context_detection(self):
        p = Privatiser()
        text = '密码 = "mysecretpass"'
        result, mapping = p.anonymize(text)
        assert "mysecretpass" not in result

    def test_japanese_context_detection(self):
        p = Privatiser()
        text = 'パスワード = "nihongo123"'
        result, mapping = p.anonymize(text)
        assert "nihongo123" not in result

    def test_russian_context_detection(self):
        p = Privatiser()
        text = 'пароль для сервера не найден: пароль = "russkiy123"'
        result, mapping = p.anonymize(text)
        assert "russkiy123" not in result

    def test_english_still_works(self):
        p = Privatiser()
        text = 'password = "english123"'
        result, mapping = p.anonymize(text)
        assert "english123" not in result

    def test_deanonymize_roundtrip(self):
        p = Privatiser()
        text = 'mot_de_passe est dans la config: mot_de_passe = "hunter2" et cle_api = "abc123xyz"'
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text
