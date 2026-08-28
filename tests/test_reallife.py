"""Tests for real-life patterns: plates, NHS, driving licences, banking, tax, insurance, personal."""

from privatiser import Privatiser


class TestVehiclePlates:
    def test_uk_plate(self):
        p = Privatiser()
        text = "car reg: AB12 CDE"
        result, mapping = p.anonymize(text)
        assert "AB12 CDE" not in result

    def test_us_plate_with_context(self):
        p = Privatiser()
        text = "license plate: ABC-1234"
        result, mapping = p.anonymize(text)
        assert "ABC-1234" not in result

    def test_eu_plate_with_context(self):
        p = Privatiser()
        text = "kennzeichen: B-AB 1234"
        result, mapping = p.anonymize(text)
        assert "B-AB 1234" not in result


class TestHealthcareIDs:
    def test_nhs_number(self):
        p = Privatiser()
        text = "NHS number: 943 476 5919"
        result, mapping = p.anonymize(text)
        assert "943 476 5919" not in result

    def test_nhs_no_space(self):
        p = Privatiser()
        text = "NHS: 9434765919"
        result, mapping = p.anonymize(text)
        assert "9434765919" not in result

    def test_medicare_id(self):
        p = Privatiser()
        text = "Medicare: 1EG4TE5MK72"
        result, mapping = p.anonymize(text)
        assert "1EG4TE5MK72" not in result

    def test_insurance_policy(self):
        p = Privatiser()
        text = "policy number: XYZ123456789"
        result, mapping = p.anonymize(text)
        assert "XYZ123456789" not in result

    def test_member_id(self):
        p = Privatiser()
        text = "member ID: MBR00123456"
        result, mapping = p.anonymize(text)
        assert "MBR00123456" not in result

    def test_group_number(self):
        p = Privatiser()
        text = "group number: GRP998877"
        result, mapping = p.anonymize(text)
        assert "GRP998877" not in result


class TestDrivingLicences:
    def test_uk_driving_licence(self):
        p = Privatiser()
        text = "driving licence: JONES710238AB9CD"
        result, mapping = p.anonymize(text)
        assert "JONES710238AB9CD" not in result

    def test_us_drivers_licence(self):
        p = Privatiser()
        text = "driver's license: D12345678"
        result, mapping = p.anonymize(text)
        assert "D12345678" not in result

    def test_dl_abbreviation(self):
        p = Privatiser()
        text = "DL# A1234567"
        result, mapping = p.anonymize(text)
        assert "A1234567" not in result


class TestBanking:
    def test_sort_code(self):
        p = Privatiser()
        text = "sort code: 20-00-00"
        result, mapping = p.anonymize(text)
        assert "20-00-00" not in result

    def test_routing_number(self):
        p = Privatiser()
        text = "routing number: 021000021"
        result, mapping = p.anonymize(text)
        assert "021000021" not in result

    def test_bank_account_number(self):
        p = Privatiser()
        text = "account number: 12345678"
        result, mapping = p.anonymize(text)
        assert "12345678" not in result

    def test_checking_account(self):
        p = Privatiser()
        text = "checking: 9876543210"
        result, mapping = p.anonymize(text)
        assert "9876543210" not in result

    def test_swift_code(self):
        p = Privatiser()
        text = "SWIFT code: BARCGB22"
        result, mapping = p.anonymize(text)
        assert "BARCGB22" not in result

    def test_bic_code(self):
        p = Privatiser()
        text = "BIC: DEUTDEFF"
        result, mapping = p.anonymize(text)
        assert "DEUTDEFF" not in result


class TestTaxReferences:
    def test_uk_utr(self):
        p = Privatiser()
        text = "UTR: 1234567890"
        result, mapping = p.anonymize(text)
        assert "1234567890" not in result

    def test_uk_nino(self):
        p = Privatiser()
        text = "NINO: AB 12 34 56 C"
        result, mapping = p.anonymize(text)
        assert "AB 12 34 56 C" not in result

    def test_us_ein(self):
        p = Privatiser()
        text = "EIN: 12-3456789"
        result, mapping = p.anonymize(text)
        assert "12-3456789" not in result

    def test_us_itin(self):
        p = Privatiser()
        text = "ITIN: 912-34-5678"
        result, mapping = p.anonymize(text)
        assert "912-34-5678" not in result


class TestInsurance:
    def test_vin(self):
        p = Privatiser()
        text = "VIN: 1HGBH41JXMN109186"
        result, mapping = p.anonymize(text)
        assert "1HGBH41JXMN109186" not in result

    def test_claim_number(self):
        p = Privatiser()
        text = "claim number: CLM-2024-123456"
        result, mapping = p.anonymize(text)
        assert "CLM-2024-123456" not in result

    def test_reference_number(self):
        p = Privatiser()
        text = "reference number: REF-ABC-123"
        result, mapping = p.anonymize(text)
        assert "REF-ABC-123" not in result

    def test_order_number(self):
        p = Privatiser()
        text = "order number: ORD-99887766"
        result, mapping = p.anonymize(text)
        assert "ORD-99887766" not in result

    def test_booking_ref(self):
        p = Privatiser()
        text = "booking ref: ABCDEF"
        result, mapping = p.anonymize(text)
        assert "ABCDEF" not in result

    def test_tracking_number(self):
        p = Privatiser()
        text = "tracking number: 1Z999AA10123456784"
        result, mapping = p.anonymize(text)
        assert "1Z999AA10123456784" not in result


class TestPersonalInfo:
    def test_dob(self):
        p = Privatiser()
        text = "DOB: 15/03/1990"
        result, mapping = p.anonymize(text)
        assert "15/03/1990" not in result

    def test_date_of_birth(self):
        p = Privatiser()
        text = "date of birth: 03-15-1990"
        result, mapping = p.anonymize(text)
        assert "03-15-1990" not in result

    def test_age(self):
        p = Privatiser()
        text = "age: 34 years old"
        result, mapping = p.anonymize(text)
        assert "34" not in result or "[AGE]" in result

    def test_gender(self):
        p = Privatiser()
        text = "gender: female"
        result, mapping = p.anonymize(text)
        assert "female" not in result

    def test_nationality(self):
        p = Privatiser()
        text = "nationality: British"
        result, mapping = p.anonymize(text)
        assert "British" not in result

    def test_religion(self):
        p = Privatiser()
        text = "religion: Christianity"
        result, mapping = p.anonymize(text)
        assert "Christianity" not in result

    def test_roundtrip_dob(self):
        p = Privatiser()
        text = "DOB: 25/12/1985"
        result, mapping = p.anonymize(text)
        restored = p.deanonymize(result, mapping)
        assert restored == text
