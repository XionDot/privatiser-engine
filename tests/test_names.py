"""Tests for person name detection."""

from privatiser import Privatiser


class TestNameDetection:
    def test_basic_first_last(self):
        p = Privatiser()
        result, mapping = p.anonymize("Patient: John Smith")
        assert "John Smith" not in result
        assert "[PERSON_1]" in result

    def test_female_name(self):
        p = Privatiser()
        result, _ = p.anonymize("contact Sarah Johnson at the clinic")
        assert "Sarah Johnson" not in result

    def test_name_with_title(self):
        p = Privatiser()
        result, _ = p.anonymize("Dr. Emily Davis reviewed the case")
        assert "Emily Davis" not in result

    def test_roundtrip(self):
        p = Privatiser()
        text = "Patient: John Smith, DOB: 15/03/1990"
        result, mapping = p.anonymize(text)
        assert "John Smith" not in result
        restored = p.deanonymize(result, mapping)
        assert restored == text

    def test_two_different_names(self):
        p = Privatiser()
        result, mapping = p.anonymize("John Smith and Sarah Johnson attended")
        assert "John Smith" not in result
        assert "Sarah Johnson" not in result
        assert len([v for v in mapping.values() if v in ("John Smith", "Sarah Johnson")]) == 2

    def test_same_name_twice_same_pseudonym(self):
        p = Privatiser()
        text = "John Smith called John Smith back"
        result, mapping = p.anonymize(text)
        assert result.count("[PERSON_1]") == 2

    def test_unknown_name_not_redacted(self):
        p = Privatiser()
        result, mapping = p.anonymize("Zxqvbf Plmnkrt attended the meeting")
        assert "Zxqvbf Plmnkrt" in result
        assert mapping == {}

    def test_common_word_false_positive_grace(self):
        p = Privatiser()
        result, _ = p.anonymize("grace period expires soon")
        assert "grace period" in result.lower()

    def test_common_word_false_positive_mark(self):
        p = Privatiser()
        result, _ = p.anonymize("mark down the date")
        assert result == "mark down the date"

    def test_common_word_false_positive_will(self):
        p = Privatiser()
        result, _ = p.anonymize("will the server restart")
        assert result == "will the server restart"

    def test_known_place_not_redacted(self):
        """Jordan River - Jordan is a first name but River is not a surname."""
        p = Privatiser()
        result, mapping = p.anonymize("Jordan River flows south")
        assert "Jordan River" in result

    def test_name_alongside_other_patterns(self):
        p = Privatiser()
        text = "Patient: Jane Smith, email: jane@clinic.com, NHS number: 943 476 5919"
        result, mapping = p.anonymize(text)
        assert "Jane Smith" not in result
        assert "jane@clinic.com" not in result
        assert "943 476 5919" not in result
        restored = p.deanonymize(result, mapping)
        assert restored == text
