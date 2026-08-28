"""Language detection for multi-language pattern matching."""

from __future__ import annotations

import re


# Character range detectors
_CJK_RANGE = re.compile(r"[\u4e00-\u9fff\u3400-\u4dbf]")  # Chinese
_HIRAGANA = re.compile(r"[\u3040-\u309f]")
_KATAKANA = re.compile(r"[\u30a0-\u30ff]")
_HANGUL = re.compile(r"[\uac00-\ud7af\u1100-\u11ff]")
_CYRILLIC = re.compile(r"[\u0400-\u04ff]")
_ARABIC = re.compile(r"[\u0600-\u06ff]")
_DEVANAGARI = re.compile(r"[\u0900-\u097f]")

# Common word markers for Latin-script languages
_LANG_MARKERS: dict[str, list[str]] = {
    "fr": [
        "le", "la", "les", "un", "une", "des", "du", "de", "est", "sont",
        "avec", "pour", "dans", "sur", "par", "cette", "ce", "mais", "ou",
        "mot_de_passe", "cle_api", "jeton", "utilisateur", "serveur",
    ],
    "es": [
        "el", "la", "los", "las", "un", "una", "es", "son", "con", "para",
        "del", "por", "pero", "como", "esta", "ese", "eso", "entre",
        "contraseña", "clave", "clave_api", "usuario", "servidor",
    ],
    "de": [
        "der", "die", "das", "ein", "eine", "ist", "sind", "mit", "und",
        "auf", "von", "nicht", "wird", "aber", "oder", "nach", "bei",
        "passwort", "kennwort", "schlüssel", "geheimnis", "benutzer",
    ],
    "pt": [
        "o", "os", "um", "uma", "do", "da", "no", "na", "com", "para",
        "por", "mas", "como", "quando", "entre", "sobre", "mais",
        "senha", "chave", "chave_api", "segredo", "servidor", "usuario",
    ],
    "it": [
        "il", "lo", "la", "gli", "le", "un", "una", "del", "nel", "con",
        "per", "tra", "fra", "sono", "come", "questo", "quello",
        "chiave", "chiave_api", "segreto", "utente",
    ],
    "nl": [
        "de", "het", "een", "van", "in", "op", "met", "voor", "aan",
        "maar", "ook", "niet", "wel", "naar", "bij",
        "wachtwoord", "sleutel", "geheim", "api_sleutel", "gebruiker",
    ],
    "ru": [
        "и", "в", "на", "не", "что", "это", "для", "как", "из", "от",
        "по", "но", "или", "при", "все", "так",
    ],
}


def detect_languages(text: str) -> set[str]:
    """Detect which languages are present in the text.

    Returns a set of language codes. Always includes 'en'.
    Script-based detection is definitive (CJK, Cyrillic, etc.).
    Latin-script languages are detected by common word frequency.
    """
    detected: set[str] = {"en"}  # English always active

    # Script-based detection (definitive)
    if _CJK_RANGE.search(text):
        detected.add("zh")
    if _HIRAGANA.search(text) or _KATAKANA.search(text):
        detected.add("ja")
    if _HANGUL.search(text):
        detected.add("ko")
    if _CYRILLIC.search(text):
        detected.add("ru")
    if _ARABIC.search(text):
        detected.add("ar")
    if _DEVANAGARI.search(text):
        detected.add("hi")

    # Latin-script language detection via word frequency
    lower = text.lower()
    words = set(re.findall(r"\b[a-zA-ZÀ-ÿ_]{2,}\b", lower))

    for lang, markers in _LANG_MARKERS.items():
        hits = sum(1 for m in markers if m in words)
        # Need at least 1 marker hit to flag a language
        if hits >= 1:
            detected.add(lang)

    return detected


def get_secret_keywords(languages: set[str]) -> list[str]:
    """Return secret keywords for the detected languages.

    These are words that indicate a value is a secret/credential
    when used in key=value patterns.
    """
    keywords: list[str] = []

    if "en" in languages:
        # English is already in the main pattern, skip here
        pass

    if "fr" in languages:
        keywords.extend([
            "mot de passe", "mot_de_passe", "mdp", "motdepasse",
            "clé api", "cle_api", "clé secrète", "cle_secrete",
            "clé privée", "cle_privee",
            "jeton", "jeton_api", "jeton_acces",
            "identifiant", "secret_api",
            "cle_chiffrement", "cle_signature",
            "mot passe admin", "mot_passe_admin",
            "mot passe root", "mot_passe_root",
            "mot passe db", "mot_passe_db", "mot_passe_bdd",
        ])

    if "es" in languages:
        keywords.extend([
            "contraseña", "contrasena", "clave",
            "clave api", "clave_api", "clave secreta", "clave_secreta",
            "clave privada", "clave_privada",
            "clave acceso", "clave_acceso", "secreto", "secreto_api",
            "token acceso", "token_acceso", "token_api",
            "clave_cifrado", "clave_firma",
            "contrasena_admin", "contrasena_root",
            "contrasena_bd", "contrasena_db",
        ])

    if "de" in languages:
        keywords.extend([
            "passwort", "kennwort", "kenncode",
            "geheimnis", "geheim", "schlüssel", "schluessel",
            "api schlüssel", "api_schlüssel", "api_schluessel",
            "geheimer schlüssel", "geheimer_schlüssel", "geheimer_schluessel",
            "zugangsschlüssel", "zugangsschluessel",
            "privater schlüssel", "privater_schlüssel", "privater_schluessel",
            "admin passwort", "admin_passwort",
            "root_passwort", "db_passwort", "datenbank_passwort",
        ])

    if "pt" in languages:
        keywords.extend([
            "senha", "senha_api", "senha secreta", "senha_secreta",
            "chave", "chave_api", "chave secreta", "chave_secreta",
            "chave privada", "chave_privada",
            "chave acesso", "chave_acesso",
            "segredo", "segredo_api",
            "token acesso", "token_acesso", "token_api",
            "senha_admin", "senha_root",
            "senha_bd", "senha_banco",
        ])

    if "it" in languages:
        keywords.extend([
            "password", "parola chiave", "parola_chiave",
            "parola d'ordine", "parola_dordine",
            "chiave", "chiave_api", "chiave segreta", "chiave_segreta",
            "chiave privata", "chiave_privata",
            "chiave accesso", "chiave_accesso",
            "segreto", "segreto_api",
            "gettone", "gettone_api", "gettone_accesso",
            "chiave_cifratura", "chiave_firma",
            "password_admin", "password_root", "password_db",
        ])

    if "nl" in languages:
        keywords.extend([
            "wachtwoord", "toegangscode",
            "sleutel", "api sleutel", "api_sleutel",
            "geheime sleutel", "geheime_sleutel",
            "geheim", "privesleutel", "prive_sleutel",
            "toegangssleutel",
            "admin wachtwoord", "admin_wachtwoord",
            "root_wachtwoord", "db_wachtwoord", "database_wachtwoord",
        ])

    if "ja" in languages:
        keywords.extend([
            "パスワード", "暗証番号", "秘密鍵",
            "APIキー", "アクセスキー", "シークレット",
            "トークン", "認証キー", "暗号鍵",
        ])

    if "zh" in languages:
        keywords.extend([
            "密码", "口令", "密钥", "秘钥",
            "访问密钥", "私钥", "公钥",
            "令牌", "凭证", "凭据",
            "加密密钥", "签名密钥",
        ])

    if "ko" in languages:
        keywords.extend([
            "비밀번호", "암호", "비밀키",
            "접근키", "인증키", "토큰",
            "개인키", "공개키", "자격증명",
        ])

    if "ru" in languages:
        keywords.extend([
            "пароль", "секрет", "ключ",
            "секретный_ключ", "api_ключ",
            "токен", "маркер", "доступ",
            "закрытый_ключ", "приватный_ключ",
            "пароль_админа", "пароль_бд",
        ])

    if "ar" in languages:
        keywords.extend([
            "كلمة المرور", "كلمة_المرور",
            "كلمة السر", "كلمةالسر",
            "مفتاح الوصول", "مفتاح_الوصول",
            "السر", "رمز الوصول", "رمز_الوصول",
            "مفتاح الأبراج", "الرمز السري",
        ])

    if "hi" in languages:
        keywords.extend([
            "पासवर्ड", "गुप्त कुंजी", "गुप्तकुंजी",
            "प्रमाणीकरण कुंजी", "एपीआई कुंजी",
            "टोकन", "प्राइवेट कुंजी",
        ])

    return keywords
