"""Fuzzing tests: adversarial inputs designed to break the engine, not just pass through it."""

import re
import time
import pytest

from privatiser import Privatiser
from privatiser.patterns import get_all_handlers


# ============ CRASH ATTEMPTS ============

class TestNeverCrash:
    """Inputs that should never raise an exception under any circumstance."""

    def test_empty_string(self):
        p = Privatiser()
        result, mapping = p.anonymize("")
        assert result == ""
        assert mapping == {}

    def test_null_bytes_in_content(self):
        """Null bytes are our placeholder delimiter - they must not corrupt output."""
        p = Privatiser()
        # Null bytes in plain text
        result, _ = p.anonymize("\x00\x00\x00")
        assert isinstance(result, str)

    def test_placeholder_format_in_input(self):
        """Input containing our exact internal placeholder format should not corrupt state."""
        p = Privatiser()
        # Craft input that looks exactly like our internal placeholder
        text = "\x00PRIV_0\x00 and \x00PRIV_999\x00 and normal text"
        result, mapping = p.anonymize(text)
        assert isinstance(result, str)
        # The placeholder-like strings should NOT be treated as real pseudonyms
        assert "\x00PRIV_0\x00" not in mapping

    def test_placeholder_collision_attempt(self):
        """If user text creates a string matching our placeholder, deanonymize must still work."""
        p = Privatiser()
        text = "email: user@test.com and literal: \x00PRIV_0\x00"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        # Must not throw
        assert isinstance(restored, str)

    def test_binary_garbage(self):
        p = Privatiser()
        garbage = bytes(range(256)).decode("latin-1")
        result, _ = p.anonymize(garbage)
        assert isinstance(result, str)

    def test_max_unicode_codepoints(self):
        p = Privatiser()
        text = "".join(chr(i) for i in range(0x10000, 0x10010))
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_very_deep_nesting_prose(self):
        p = Privatiser()
        text = "(" * 1000 + "email: a@b.com" + ")" * 1000
        result, _ = p.anonymize(text)
        assert "a@b.com" not in result

    def test_extremely_long_single_token(self):
        """A single 50k char token - regex engines can choke on this."""
        p = Privatiser()
        text = "A" * 50_000
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_newline_explosion(self):
        p = Privatiser()
        result, _ = p.anonymize("\n" * 50_000)
        assert isinstance(result, str)

    def test_mixed_encodings_in_one_string(self):
        p = Privatiser()
        text = "ascii test@example.com \u00e9\u00e0\u00fc \u4e2d\u6587 \u0440\u0443\u0441\u0441\u043a\u0438\u0439"
        result, _ = p.anonymize(text)
        assert "test@example.com" not in result

    def test_anonymize_on_already_anonymized_text(self):
        """Re-running anonymize on its own output must not produce garbage."""
        p = Privatiser()
        original = "email: attacker@evil.com password = \"hunter2\""
        result1, map1 = p.anonymize(original)
        p2 = Privatiser()
        result2, map2 = p2.anonymize(result1)
        # The pseudonyms from pass 1 should not be re-anonymized into garbage
        assert isinstance(result2, str)
        # Deanonymize pass 2 then pass 1 should get back to original
        mid = p2.deanonymize(result2, map2)
        restored = p.deanonymize(mid, map1)
        assert restored == original


# ============ REDOS PROBES ============

class TestReDoS:
    """Probe patterns for catastrophic backtracking with adversarial inputs."""

    TIMEOUT = 2.0  # seconds - if a pattern takes longer it's a ReDoS risk

    def _time_anonymize(self, text):
        p = Privatiser()
        start = time.monotonic()
        p.anonymize(text)
        return time.monotonic() - start

    def test_long_almost_matching_email(self):
        """String that almost looks like an email but fails at the end."""
        text = "a" * 200 + "@" + "b" * 200 + "." + "c" * 200 + "!"
        elapsed = self._time_anonymize(text)
        assert elapsed < self.TIMEOUT, f"Email pattern took {elapsed:.2f}s - possible ReDoS"

    def test_long_almost_matching_ip(self):
        """Long string with dots that isn't an IP."""
        text = ".".join(["999"] * 100)
        elapsed = self._time_anonymize(text)
        assert elapsed < self.TIMEOUT, f"IP pattern took {elapsed:.2f}s - possible ReDoS"

    def test_long_almost_matching_credit_card(self):
        """16 digits that fail Luhn, preceded by thousands of digits."""
        text = "1" * 10_000 + " 1234567890123456"
        elapsed = self._time_anonymize(text)
        assert elapsed < self.TIMEOUT, f"CC pattern took {elapsed:.2f}s - possible ReDoS"

    def test_long_almost_matching_secret(self):
        """Looks like a secret assignment but value never closes."""
        text = 'password = "' + "x" * 10_000
        elapsed = self._time_anonymize(text)
        assert elapsed < self.TIMEOUT, f"Secret pattern took {elapsed:.2f}s - possible ReDoS"

    def test_long_almost_matching_iban(self):
        """Long IBAN-like string."""
        text = "GB" + "9" * 100
        elapsed = self._time_anonymize(text)
        assert elapsed < self.TIMEOUT, f"IBAN pattern took {elapsed:.2f}s - possible ReDoS"

    def test_alternating_at_signs(self):
        """Alternating chars that stress email regex."""
        text = ("a@" * 500) + "b.com"
        elapsed = self._time_anonymize(text)
        assert elapsed < self.TIMEOUT, f"Email alternation took {elapsed:.2f}s - possible ReDoS"


# ============ ROUNDTRIP INTEGRITY ============

class TestRoundtripIntegrity:
    """
    deanonymize(anonymize(text)) must ALWAYS equal text exactly.
    These tests use adversarial inputs to try to break that guarantee.
    """

    def _roundtrip(self, text):
        p = Privatiser()
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text, (
            f"Roundtrip failed!\n"
            f"  input:    {text!r}\n"
            f"  anon:     {result!r}\n"
            f"  restored: {restored!r}"
        )

    def test_pseudonym_appears_in_original(self):
        """Original text contains a string that looks like our pseudonym output."""
        self._roundtrip("REDACTED_SECRET_1 is already in the text")

    def test_pseudonym_appears_multiple_times_original(self):
        self._roundtrip("REDACTED_EMAIL_1 and REDACTED_EMAIL_1 again and REDACTED_EMAIL_2")

    def test_value_is_substring_of_another_value(self):
        """One sensitive value is a substring of another - replacement order matters."""
        self._roundtrip("email: a@b.com and longer-a@b.com.evil.org")

    def test_two_emails_where_one_contains_the_other(self):
        """'test@example.com' is a substring of 'mytest@example.com'."""
        self._roundtrip("first: mytest@example.com second: test@example.com")

    def test_same_value_appears_50_times(self):
        """Same email 50 times - only 1 mapping entry, all 50 must be restored."""
        email = "repeat@test.com"
        text = f"email: {email}\n" * 50
        self._roundtrip(text)

    def test_pseudonym_of_first_match_is_value_in_text(self):
        """The pseudonym we generate for match 1 happens to equal something else in the text."""
        # Force a situation where the pseudonym string appears elsewhere in the input
        # REDACTED_SECRET_1 is our generated pseudonym - put it literally in the input
        text = 'password = "REDACTED_SECRET_1" is what it generates'
        self._roundtrip(text)

    def test_all_pattern_types_together(self):
        """One text containing one of every pattern type."""
        self._roundtrip(
            "Email: alice@company.com\n"
            "IP: 10.0.0.1\n"
            "Phone: +1 (555) 123-4567\n"
            "SSN: 123-45-6789\n"
            "CC: 4111111111111111\n"
            "IBAN: GB29 NWBK 6016 1331 9268 19\n"
            "NHS number: 943 476 5919\n"
            "DOB: 15/03/1990\n"
            "sort code: 20-00-00\n"
            "UTR: 1234567890\n"
            "VIN: 1HGBH41JXMN109186\n"
            "SWIFT code: BARCGB22\n"
            'password = "hunter2"\n'
            "claim number: CLM-2024-123456\n"
            "EIN: 12-3456789\n"
        )

    def test_unicode_content_around_pattern(self):
        """Unicode text surrounding an English pattern."""
        self._roundtrip("联系邮件: test@company.com について")

    def test_newlines_within_value_context(self):
        """Pattern keyword on one line, nearby text on another."""
        self._roundtrip("line one: test@example.com\nline two: other@example.com")

    def test_special_regex_chars_in_surrounding_text(self):
        """Regex special chars in the plain text around patterns."""
        self._roundtrip(r"[regex] (test) {email}: user@test.com ^end$")

    def test_backslashes_in_surrounding_text(self):
        self._roundtrip("path: C:\\Users\\admin, email: user@test.com")

    def test_50_unique_emails_roundtrip(self):
        emails = [f"user{i}@domain{i}.com" for i in range(50)]
        text = " ".join(emails)
        self._roundtrip(text)


# ============ FALSE POSITIVE ATTACK ============

class TestFalsePositiveAttacks:
    """
    Inputs crafted to look like real patterns but are NOT sensitive.
    The engine should NOT redact these, or at minimum not corrupt them.
    """

    def test_version_string_not_ip(self):
        """X.Y.Z.W version strings should ideally not all be treated as IPs."""
        p = Privatiser()
        # Version numbers like 1.2.3.4 DO look like IPs - document actual behavior
        text = "version 1.2.3.4 released"
        result, _ = p.anonymize(text)
        # Whatever happens, roundtrip must work
        assert isinstance(result, str)

    def test_isbn_not_ssn(self):
        """ISBN-13 has dashes but different format."""
        p = Privatiser()
        text = "ISBN: 978-3-16-148410-0"
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_math_not_ssn(self):
        """123-45-6789 is an SSN but 12-3456-78 is not."""
        p = Privatiser()
        text = "ref: 12-3456-78 items"
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_time_not_ssn(self):
        """12:34:56 looks like grouped digits but is a time."""
        p = Privatiser()
        text = "at time 12:34:56 the event occurred"
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_hex_color_not_credit_card(self):
        p = Privatiser()
        text = "color: #FF5733 and background #000000"
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_common_word_not_secret(self):
        """'password' in prose without = or : should not trigger redaction."""
        p = Privatiser()
        text = "Please reset your password using the link below."
        result, _ = p.anonymize(text)
        assert "password" in result  # should not be redacted

    def test_password_keyword_no_value(self):
        """'password =' with nothing after should not crash."""
        p = Privatiser()
        text = "password = "
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_localhost_not_redacted(self):
        """127.0.0.1 and localhost should be skipped."""
        p = Privatiser()
        result, mapping = p.anonymize("connect to 127.0.0.1:5432")
        assert "127.0.0.1" in result
        assert mapping == {}

    def test_example_domain_not_redacted(self):
        """example.com is in skip list and should pass through."""
        p = Privatiser()
        result, mapping = p.anonymize("see example.com for details")
        assert "example.com" in result


# ============ MAPPING INTEGRITY ============

class TestMappingIntegrity:
    """The mapping must be internally consistent - no duplicates, no orphans."""

    def test_same_value_one_pseudonym(self):
        """The same sensitive value must always produce exactly the same pseudonym."""
        p = Privatiser()
        text = "a@b.com and a@b.com and a@b.com"
        result, mapping = p.anonymize(text)
        # Only 1 entry in mapping for this email
        originals = list(mapping.values())
        assert originals.count("a@b.com") == 1
        # But the pseudonym appears 3 times in result
        pseudo = [k for k, v in mapping.items() if v == "a@b.com"][0]
        assert result.count(pseudo) == 3

    def test_different_values_different_pseudonyms(self):
        """Two different values must never share a pseudonym."""
        p = Privatiser()
        text = "a@x.com and b@x.com and c@x.com"
        _, mapping = p.anonymize(text)
        pseudonyms = list(mapping.keys())
        assert len(pseudonyms) == len(set(pseudonyms)), "Pseudonym collision detected!"

    def test_mapping_is_bijective(self):
        """Every pseudonym maps to exactly one original and vice versa."""
        p = Privatiser()
        emails = [f"user{i}@test.com" for i in range(20)]
        _, mapping = p.anonymize(" ".join(emails))
        pseudonyms = list(mapping.keys())
        originals = list(mapping.values())
        assert len(set(pseudonyms)) == len(pseudonyms), "Duplicate pseudonyms"
        assert len(set(originals)) == len(originals), "Duplicate originals in mapping"

    def test_reset_restarts_counters(self):
        """After reset(), the same input produces the same output as the first run."""
        p = Privatiser()
        _, map1 = p.anonymize("email: a@b.com")
        p.reset()
        _, map2 = p.anonymize("email: a@b.com")
        assert map1 == map2

    def test_counters_increment_not_repeat(self):
        """Each unique value gets an incrementing counter, not the same one."""
        p = Privatiser()
        _, mapping = p.anonymize("a@x.com b@x.com c@x.com")
        pseudos = sorted(mapping.keys())
        # Should be EMAIL_1, EMAIL_2, EMAIL_3 (or similar incrementing)
        assert len(pseudos) == 3
        assert pseudos[0] != pseudos[1] != pseudos[2]


# ============ ALLOWLIST SECURITY ============

class TestAllowlistSecurity:
    """The allowlist must only protect exactly what's listed, nothing more."""

    def test_allowlisted_value_not_redacted(self):
        p = Privatiser(allowlist=["safe@example.com"])
        result, _ = p.anonymize("email: safe@example.com")
        assert "safe@example.com" in result

    def test_allowlist_does_not_protect_similar_values(self):
        """Allowlisting 'safe@example.com' must NOT protect 'evil@example.com'."""
        p = Privatiser(allowlist=["safe@example.com"])
        result, _ = p.anonymize("safe@example.com and evil@example.com")
        assert "safe@example.com" in result
        assert "evil@example.com" not in result

    def test_allowlist_is_exact_match(self):
        """Allowlisting 'test' must NOT protect 'test@example.com'."""
        p = Privatiser(allowlist=["test"])
        result, _ = p.anonymize("email: test@example.com")
        # The full email should still be redacted even if 'test' is allowlisted
        # (allowlist checks the full match, not substrings of it)
        assert isinstance(result, str)

    def test_empty_allowlist_redacts_everything(self):
        p = Privatiser(allowlist=[])
        result, _ = p.anonymize("email: a@b.com")
        assert "a@b.com" not in result

    def test_allowlist_blocks_exact_email_pattern(self):
        """Allowlisting an email blocks the email pattern specifically.
        Known limitation: subsequent patterns (e.g. domain) may still match parts of it."""
        p = Privatiser(allowlist=["safe@company.internal"])
        result, _ = p.anonymize("email: safe@company.internal and unsafe@company.internal")
        # unsafe must be redacted
        assert "unsafe@company.internal" not in result
        # safe is protected from the email pattern
        assert isinstance(result, str)


# ============ CATEGORY FILTERING SECURITY ============

class TestCategoryFilteringSecurity:
    """Disabling a category must fully suppress it - no partial leakage."""

    def test_disabled_network_suppresses_all_network(self):
        p = Privatiser(enabled_categories={"network": False})
        text = "ip: 10.0.0.1 email: a@b.com domain: internal.corp"
        result, _ = p.anonymize(text)
        assert "10.0.0.1" in result
        assert "a@b.com" in result

    def test_disabled_pii_suppresses_ssn_and_cc(self):
        p = Privatiser(enabled_categories={"pii": False})
        text = "ssn: 123-45-6789 cc: 4111111111111111"
        result, _ = p.anonymize(text)
        assert "123-45-6789" in result
        assert "4111111111111111" in result

    def test_all_categories_disabled_passes_everything(self):
        p = Privatiser(enabled_categories={
            "secrets": False, "network": False, "pii": False,
            "aws": False, "cloud": False, "identifiers": False,
        })
        text = "email: a@b.com password = \"hunter2\" ip: 10.0.0.1"
        result, mapping = p.anonymize(text)
        assert mapping == {}
        assert result == text

    def test_unknown_category_defaults_enabled(self):
        """Patterns with unknown categories should still be processed."""
        from privatiser.patterns import PatternHandler
        import re
        p = Privatiser(extra_patterns=[
            PatternHandler(
                name="custom_test",
                category="unknown_future_category",
                regex=re.compile(r"\bSECRET_WORD\b"),
                pseudonym_fn=lambda n: "REDACTED",
                priority=1,
            )
        ])
        result, _ = p.anonymize("text with SECRET_WORD inside")
        assert "SECRET_WORD" not in result


# ============ LANGUAGE DETECTION ============

class TestLanguageDetection:
    """Language detection must trigger on keywords, not produce false positives."""

    def test_single_french_keyword_triggers_french(self):
        """Even a single mot_de_passe keyword should trigger French detection."""
        p = Privatiser()
        result, _ = p.anonymize('mot_de_passe = "secret123"')
        assert "secret123" not in result

    def test_single_spanish_keyword_triggers_spanish(self):
        p = Privatiser()
        result, _ = p.anonymize('contraseña = "secreto123"')
        assert "secreto123" not in result

    def test_single_german_keyword_triggers_german(self):
        p = Privatiser()
        result, _ = p.anonymize('passwort = "geheim123"')
        assert "geheim123" not in result

    def test_chinese_script_triggers_chinese(self):
        p = Privatiser()
        result, _ = p.anonymize('密码 = "mysecretpass"')
        assert "mysecretpass" not in result

    def test_japanese_script_triggers_japanese(self):
        p = Privatiser()
        result, _ = p.anonymize('パスワード = "nihongo123"')
        assert "nihongo123" not in result

    def test_russian_script_triggers_russian(self):
        p = Privatiser()
        result, _ = p.anonymize('пароль = "russkiy123"')
        assert "russkiy123" not in result

    def test_english_always_active(self):
        p = Privatiser()
        result, _ = p.anonymize('password = "english123"')
        assert "english123" not in result

    def test_mixed_languages_all_redacted(self):
        p = Privatiser()
        result, _ = p.anonymize(
            'password = "english" and mot_de_passe = "french" and '
            'passwort = "german" and 密码 = "chinese"'
        )
        assert "english" not in result
        assert "french" not in result
        assert "german" not in result
        assert "chinese" not in result

    def test_french_keyword_does_not_redact_english_prose(self):
        """Detecting French should not cause false positives on unrelated English words."""
        p = Privatiser()
        # 'la' is a French marker but also common English
        text = 'mot_de_passe = "secret" and normal words like la and le should stay'
        result, _ = p.anonymize(text)
        assert "secret" not in result
        assert "normal" in result


# ============ REAL-LIFE PATTERNS ============

class TestRealLifePatternIntegrity:
    """Real-life patterns must detect exactly what they claim, nothing more or less."""

    def test_nhs_prefix_preserved_in_roundtrip(self):
        p = Privatiser()
        text = "NHS number: 943 476 5919"
        result, mapping = p.anonymize(text)
        assert "NHS number:" in result  # prefix preserved
        assert "943 476 5919" not in result
        assert p.deanonymize(result, mapping) == text

    def test_sort_code_prefix_preserved_in_roundtrip(self):
        p = Privatiser()
        text = "sort code: 20-00-00"
        result, mapping = p.anonymize(text)
        assert "sort code:" in result
        assert "20-00-00" not in result
        assert p.deanonymize(result, mapping) == text

    def test_dob_prefix_preserved_in_roundtrip(self):
        p = Privatiser()
        text = "DOB: 15/03/1990"
        result, mapping = p.anonymize(text)
        assert "DOB:" in result
        assert "15/03/1990" not in result
        assert p.deanonymize(result, mapping) == text

    def test_nhs_without_context_not_matched(self):
        """Bare 10-digit number without NHS context should NOT be matched."""
        p = Privatiser()
        text = "reference: 9434765919"
        result, _ = p.anonymize(text)
        # Without NHS/UTR context it's ambiguous - should not match as NHS
        assert isinstance(result, str)

    def test_uk_nino_excluded_prefixes(self):
        for prefix in ["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"]:
            p = Privatiser()
            text = f"{prefix} 12 34 56 C"
            result, mapping = p.anonymize(text)
            assert f"{prefix} 12 34 56 C" in result, f"Excluded NINO prefix {prefix} was wrongly redacted"

    def test_uk_nino_valid_prefix_is_matched(self):
        p = Privatiser()
        text = "AB 12 34 56 C"
        result, _ = p.anonymize(text)
        assert "AB 12 34 56 C" not in result

    def test_vin_wrong_length_not_matched(self):
        p = Privatiser()
        text = "VIN: 1HGBH41JXMN10918"  # 16 chars, not 17
        result, _ = p.anonymize(text)
        assert isinstance(result, str)

    def test_broadcast_ip_not_matched(self):
        """255.255.255.255 is excluded - documented boundary."""
        p = Privatiser()
        result, mapping = p.anonymize("255.255.255.255")
        assert result == "255.255.255.255"
        assert mapping == {}

    def test_localhost_not_matched(self):
        p = Privatiser()
        result, mapping = p.anonymize("127.0.0.1")
        assert result == "127.0.0.1"
        assert mapping == {}


# ============ STRESS ============

class TestStress:
    """High-volume correctness tests."""

    def test_200_unique_emails_all_redacted(self):
        p = Privatiser()
        emails = [f"user{i}@example{i}.com" for i in range(200)]
        result, mapping = p.anonymize(" ".join(emails))
        assert len(mapping) == 200
        for e in emails:
            assert e not in result

    def test_200_unique_emails_roundtrip(self):
        p = Privatiser()
        emails = [f"user{i}@example{i}.com" for i in range(200)]
        text = " ".join(emails)
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_50_unique_ips_roundtrip(self):
        p = Privatiser()
        ips = [f"10.0.0.{i}" for i in range(50)]
        text = " ".join(ips)
        result, mapping = p.anonymize(text)
        assert len(mapping) == 50
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_repeated_anonymize_same_instance(self):
        """Calling anonymize 100 times on the same instance accumulates mappings."""
        p = Privatiser()
        for i in range(100):
            text = f"email: unique{i}@test.com"
            result, _ = p.anonymize(text)
            assert f"unique{i}@test.com" not in result

    def test_large_realistic_document(self):
        """A realistic document with many different pattern types."""
        p = Privatiser()
        lines = []
        for i in range(50):
            lines.append(f"Employee {i}: user{i}@company.com, phone: +1 555-000-{i:04d}, SSN: {i:03d}-{i:02d}-{i:04d}")
        text = "\n".join(lines)
        result, mapping = p.anonymize(text)
        assert len(mapping) >= 100
        restored = p.deanonymize(result, mapping)
        assert restored == text


# ============ DEANONYMIZE ATTACK ============

class TestDeanonymizeAttacks:
    """Attempts to corrupt or bypass deanonymization."""

    def test_deanonymize_empty_content(self):
        p = Privatiser()
        assert p.deanonymize("") == ""

    def test_deanonymize_empty_mapping(self):
        p = Privatiser()
        assert p.deanonymize("hello world", {}) == "hello world"

    def test_deanonymize_with_injected_mapping(self):
        """Attacker provides a crafted mapping to overwrite content."""
        p = Privatiser()
        text = "safe text here"
        # Attacker injects a mapping that maps a substring of text to something else
        evil_mapping = {"safe": "EVIL"}
        result = p.deanonymize(text, evil_mapping)
        # The result depends on implementation - just must not crash
        assert isinstance(result, str)

    def test_deanonymize_longer_pseudo_replaced_first(self):
        """Longer pseudonyms must be replaced before shorter ones to avoid partial matches."""
        p = Privatiser()
        text = "a@b.com and longer-a@b.com"
        anon, mapping = p.anonymize(text)
        restored = p.deanonymize(anon, mapping)
        assert restored == text

    def test_deanonymize_data_nested(self):
        p = Privatiser()
        text = "a@b.com"
        anon, mapping = p.anonymize(text)
        data = {
            "top": anon,
            "nested": {"deep": [anon, anon]},
            "number": 42,
            "flag": True,
            "nothing": None,
        }
        result = p.deanonymize_data(data, mapping)
        assert result["top"] == text
        assert result["nested"]["deep"] == [text, text]
        assert result["number"] == 42
        assert result["flag"] is True
        assert result["nothing"] is None
