"""Tests for language detection module."""

from privatiser.language import detect_languages, get_secret_keywords
from privatiser import Privatiser


class TestDetectLanguages:
    def test_english_always_included(self):
        assert "en" in detect_languages("hello world")

    def test_english_only_for_english_text(self):
        langs = detect_languages("The server password is secret")
        assert langs == {"en"}

    def test_detects_french(self):
        text = "le serveur est dans la configuration avec le mot_de_passe"
        langs = detect_languages(text)
        assert "fr" in langs

    def test_detects_spanish(self):
        text = "el servidor con la contraseña para el usuario"
        langs = detect_languages(text)
        assert "es" in langs

    def test_detects_german(self):
        text = "der Server ist mit dem passwort und die Konfiguration"
        langs = detect_languages(text)
        assert "de" in langs

    def test_detects_portuguese(self):
        text = "o servidor com a senha para o usuario do sistema"
        langs = detect_languages(text)
        assert "pt" in langs

    def test_detects_italian(self):
        text = "il server con la chiave per il utente del sistema"
        langs = detect_languages(text)
        assert "it" in langs

    def test_detects_dutch(self):
        text = "de server met het wachtwoord voor de gebruiker"
        langs = detect_languages(text)
        assert "nl" in langs

    def test_detects_chinese(self):
        text = "服务器密码是这个"
        langs = detect_languages(text)
        assert "zh" in langs

    def test_detects_japanese(self):
        text = "パスワードを設定してください"
        langs = detect_languages(text)
        assert "ja" in langs

    def test_detects_korean(self):
        text = "비밀번호를 입력하세요"
        langs = detect_languages(text)
        assert "ko" in langs

    def test_detects_russian(self):
        text = "пароль для сервера не найден"
        langs = detect_languages(text)
        assert "ru" in langs

    def test_detects_multiple_languages(self):
        text = "le mot_de_passe est dans la config パスワード"
        langs = detect_languages(text)
        assert "fr" in langs
        assert "ja" in langs

    def test_no_false_positive_on_short_text(self):
        text = "x = 42"
        langs = detect_languages(text)
        assert langs == {"en"}


class TestGetSecretKeywords:
    def test_english_returns_empty(self):
        # English keywords are already in main pattern
        keywords = get_secret_keywords({"en"})
        assert keywords == []

    def test_french_keywords(self):
        keywords = get_secret_keywords({"en", "fr"})
        assert "mot_de_passe" in keywords
        assert "cle_api" in keywords

    def test_spanish_keywords(self):
        keywords = get_secret_keywords({"en", "es"})
        assert "contraseña" in keywords
        assert "clave_api" in keywords

    def test_german_keywords(self):
        keywords = get_secret_keywords({"en", "de"})
        assert "passwort" in keywords
        assert "kennwort" in keywords

    def test_chinese_keywords(self):
        keywords = get_secret_keywords({"en", "zh"})
        assert "密码" in keywords
        assert "密钥" in keywords

    def test_japanese_keywords(self):
        keywords = get_secret_keywords({"en", "ja"})
        assert "パスワード" in keywords

    def test_korean_keywords(self):
        keywords = get_secret_keywords({"en", "ko"})
        assert "비밀번호" in keywords

    def test_russian_keywords(self):
        keywords = get_secret_keywords({"en", "ru"})
        assert "пароль" in keywords

    def test_multiple_languages_combined(self):
        keywords = get_secret_keywords({"en", "fr", "de"})
        assert "mot_de_passe" in keywords
        assert "passwort" in keywords

    def test_french_space_separated_keywords(self):
        keywords = get_secret_keywords({"en", "fr"})
        assert "mot de passe" in keywords

    def test_german_space_separated_keywords(self):
        keywords = get_secret_keywords({"en", "de"})
        assert "api schlüssel" in keywords

    def test_spanish_space_separated_keywords(self):
        keywords = get_secret_keywords({"en", "es"})
        assert "clave secreta" in keywords


class TestNaturalLanguageAnonymization:
    """End-to-end tests for natural language sentences in foreign languages."""

    def test_french_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("mon mot de passe est abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_spanish_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("mi contraseña es abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_german_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("mein Passwort ist abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_portuguese_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("minha senha é abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_italian_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("la mia password è abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_dutch_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("mijn wachtwoord is abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_chinese_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("我的密码是abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_japanese_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("パスワードはabc123xyzです")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_korean_natural_language(self):
        p = Privatiser()
        result, mapping = p.anonymize("내 비밀번호는 abc123xyz입니다")
        assert "abc123xyz" not in result
        assert len(mapping) == 1

    def test_russian_natural_language(self):
        # Russian drops the copula in present tense, so colon/equals or "является" is needed
        p = Privatiser()
        result, mapping = p.anonymize("мой пароль: abc123xyz")
        assert "abc123xyz" not in result
        assert len(mapping) == 1
