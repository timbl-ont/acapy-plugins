"""Tests for encoding credential subjects as mdoc namespaces."""

import base64
from datetime import date, datetime, timezone

import cbor2
import pytest
from cbor2 import CBORTag

from mso_mdoc.mdoc.namespaces import (
    MDL,
    MDL_AAMVA,
    PHOTO_ID,
    DocumentEncodingError,
    declared_claims,
    encode_document,
    normalize_subject,
    select_profile,
    validate_claims_config,
)
from mso_mdoc.mdoc.namespaces import encoders as enc

PORTRAIT = bytes.fromhex("ffd8ffe000104a464946")
PORTRAIT_B64 = base64.b64encode(PORTRAIT).decode()

MDL_ELEMENTS = {
    "family_name": "Doe",
    "given_name": "John",
    "birth_date": "1991-06-01",
    "issue_date": "2026-01-01",
    "expiry_date": "2031-01-01",
    "issuing_country": "CA",
    "issuing_authority": "Ontario",
    "document_number": "D1234-56789-01234",
    "portrait": PORTRAIT_B64,
    "driving_privileges": [
        {
            "vehicle_category_code": "B",
            "issue_date": "2020-01-01",
            "codes": [{"code": "01", "sign": "=", "value": "glasses"}],
        }
    ],
    "un_distinguishing_sign": "CDN",
    "sex": 1,
    "age_over_18": True,
    "issuing_jurisdiction": "CA-ON",
}

AAMVA_ELEMENTS = {
    "domestic_driving_privileges": [
        {
            "domestic_vehicle_class": {
                "domestic_vehicle_class_code": "G",
                "domestic_vehicle_class_description": "Car",
                "expiry_date": "2031-01-01",
            },
            "domestic_vehicle_restrictions": [
                {"domestic_vehicle_restriction_description": "Corrective lenses"}
            ],
        }
    ],
    "family_name_truncation": "N",
    "given_name_truncation": "N",
    "sex": 1,
    "DHS_compliance": "F",
    "aka_family_name.v2": "Doe",
    "organ_donor": 1,
}

PHOTO_ID_CORE = {
    "family_name": "Smith",
    "given_name": "Alice",
    "birth_date": {"birth_date": "1990-04-01", "approximate_mask": "00000011"},
    "portrait": PORTRAIT_B64,
    "issue_date": "2026-01-01",
    "expiry_date": "2036-01-01",
    "issuing_authority": "Ontario",
    "issuing_country": "CAN",
    "age_over_18": True,
}


def decoded(encoded: dict) -> dict:
    """Decode every element value. Tag 1004 becomes a date, tag 0 a datetime."""
    return {
        ns: {el: cbor2.loads(value) for el, value in els.items()}
        for ns, els in encoded.items()
    }


def raw(encoded: dict, ns: str, el: str):
    return cbor2.loads(encoded[ns][el])


class TestEncoders:
    def test_full_date_is_tag_1004(self):
        assert enc.full_date("1990-04-01") == CBORTag(1004, "1990-04-01")
        for bad in ("1990-4-1", "1990-02-30", 19900401, "1990-04-01T00:00:00Z"):
            with pytest.raises(enc.EncodingError):
                enc.full_date(bad)

    def test_tdate_is_tag_0_in_utc_whole_seconds(self):
        assert enc.tdate("2025-12-01T10:00:00.750-05:00") == CBORTag(
            0, "2025-12-01T15:00:00Z"
        )
        for bad in ("2025-12-01", "2025-12-01T10:00:00", "noon"):
            with pytest.raises(enc.EncodingError):
                enc.tdate(bad)

    def test_tdate_or_full_date(self):
        assert enc.tdate_or_full_date("2026-01-01").tag == 1004
        assert enc.tdate_or_full_date("2026-01-01T00:00:00Z").tag == 0

    @pytest.mark.parametrize(
        "value",
        [
            PORTRAIT,
            list(PORTRAIT),
            PORTRAIT_B64,
            PORTRAIT_B64.rstrip("="),
            base64.urlsafe_b64encode(PORTRAIT).decode().rstrip("="),
            "data:image/jpeg;base64," + PORTRAIT_B64,
        ],
    )
    def test_bstr_inputs(self, value):
        assert enc.bstr(value) == PORTRAIT

    def test_bstr_rejects_text_that_is_not_base64(self):
        with pytest.raises(enc.EncodingError):
            enc.bstr("not base64!")
        with pytest.raises(enc.EncodingError):
            enc.bstr([256])

    def test_text_limits(self):
        assert enc.tstr150("é" * 150) == "é" * 150
        with pytest.raises(enc.EncodingError):
            enc.tstr150("a" * 151)
        with pytest.raises(enc.EncodingError):
            enc.latin1("東京")

    def test_integers_refuse_booleans(self):
        assert enc.uint(0) == 0
        for bad in (True, -1, "1", 1.0):
            with pytest.raises(enc.EncodingError):
                enc.uint(bad)

    def test_one_of_matches_type(self):
        sex = enc.one_of(1, 2, 9)
        assert sex(2) == 2
        for bad in ("2", True, 3):
            with pytest.raises(enc.EncodingError):
                sex(bad)

    def test_photoid_birth_date_is_always_a_map(self):
        assert enc.photoid_birth_date("1990-04-01") == {
            "birth_date": CBORTag(1004, "1990-04-01")
        }
        encoded = enc.photoid_birth_date(
            {"approximate_mask": "00000011", "birth_date": "1990-04-01"}
        )
        assert list(encoded) == ["birth_date", "approximate_mask"]
        for bad in (
            {"birth_date": "1990-04-01", "approximate_mask": "0011"},
            {"approximate_mask": "00000011"},
            {"birth_date": "1990-04-01", "extra": 1},
        ):
            with pytest.raises(enc.EncodingError):
                enc.photoid_birth_date(bad)


class TestSubjectShape:
    def test_namespaced_subject_is_kept(self):
        subject = {"org.iso.23220.1": {"family_name": "Smith"}}
        assert normalize_subject(PHOTO_ID.doctype, subject) == subject

    def test_flat_mdl_subject_is_mapped(self):
        flat = {**MDL_ELEMENTS, "org.iso.18013.5.1.aamva": AAMVA_ELEMENTS}
        namespaces = normalize_subject(MDL.doctype, flat)
        assert namespaces["org.iso.18013.5.1"] == MDL_ELEMENTS
        assert namespaces["org.iso.18013.5.1.aamva"] == AAMVA_ELEMENTS

    def test_flat_subject_is_refused_for_other_doctypes(self):
        with pytest.raises(DocumentEncodingError, match="keyed by namespace"):
            normalize_subject(PHOTO_ID.doctype, {"family_name": "Smith"})

    @pytest.mark.parametrize("subject", [None, {}, ["a"]])
    def test_empty_or_non_object_subject(self, subject):
        with pytest.raises(DocumentEncodingError):
            normalize_subject(PHOTO_ID.doctype, subject)


class TestProfiles:
    def test_selection(self):
        assert select_profile("org.iso.23220.photoid.1", {}) is PHOTO_ID
        assert select_profile("org.iso.18013.5.1.mDL", {}) is MDL
        aamva = declared_claims({"org.iso.18013.5.1.aamva": {"sex": {}}})
        assert select_profile("org.iso.18013.5.1.mDL", aamva) is MDL_AAMVA
        assert select_profile("com.example.doc", {}) is None

    def test_aamva_profile_requires_the_aamva_namespace(self):
        declared = declared_claims({"org.iso.18013.5.1.aamva": {"sex": {}}})
        with pytest.raises(DocumentEncodingError, match="org.iso.18013.5.1.aamva"):
            encode_document(MDL.doctype, {"org.iso.18013.5.1": MDL_ELEMENTS}, declared)


class TestMdl:
    def test_encodes_cbor_types(self):
        encoded = encode_document(
            MDL.doctype,
            {
                "org.iso.18013.5.1": MDL_ELEMENTS,
                "org.iso.18013.5.1.aamva": AAMVA_ELEMENTS,
            },
        )
        mdl = decoded(encoded)["org.iso.18013.5.1"]
        assert mdl["birth_date"] == date(1991, 6, 1)
        assert mdl["issue_date"] == date(2026, 1, 1)
        assert mdl["portrait"] == PORTRAIT
        assert mdl["driving_privileges"] == [
            {
                "vehicle_category_code": "B",
                "issue_date": date(2020, 1, 1),
                "codes": [{"code": "01", "sign": "=", "value": "glasses"}],
            }
        ]
        aamva = decoded(encoded)["org.iso.18013.5.1.aamva"]
        privilege = aamva["domestic_driving_privileges"][0]
        assert privilege["domestic_vehicle_class"]["expiry_date"] == date(2031, 1, 1)
        assert aamva["aka_family_name.v2"] == "Doe"

    def test_driving_privileges_defaults_to_empty(self):
        elements = {k: v for k, v in MDL_ELEMENTS.items() if k != "driving_privileges"}
        encoded = encode_document(MDL.doctype, {"org.iso.18013.5.1": elements})
        assert raw(encoded, "org.iso.18013.5.1", "driving_privileges") == []

    def test_missing_mandatory_element(self):
        elements = {k: v for k, v in MDL_ELEMENTS.items() if k != "document_number"}
        with pytest.raises(DocumentEncodingError, match="document_number"):
            encode_document(MDL.doctype, {"org.iso.18013.5.1": elements})

    def test_unknown_element_is_refused(self):
        with pytest.raises(DocumentEncodingError, match="famly_name"):
            encode_document(
                MDL.doctype,
                {"org.iso.18013.5.1": {**MDL_ELEMENTS, "famly_name": "Doe"}},
            )

    def test_jurisdiction_must_match_country(self):
        with pytest.raises(DocumentEncodingError, match="issuing_jurisdiction"):
            encode_document(
                MDL.doctype,
                {"org.iso.18013.5.1": {**MDL_ELEMENTS, "issuing_jurisdiction": "US-IA"}},
            )

    @pytest.mark.parametrize(
        "element, value",
        [
            ("sex", 3),
            ("eye_colour", "purple"),
            ("driving_privileges", [{"vehicle_category_code": "Z"}]),
        ],
    )
    def test_invalid_values(self, element, value):
        with pytest.raises(DocumentEncodingError, match=element):
            encode_document(
                MDL.doctype, {"org.iso.18013.5.1": {**MDL_ELEMENTS, element: value}}
            )

    @pytest.mark.parametrize(
        "element, value",
        [
            ("sex", 3),
            ("DHS_compliance", "Y"),
            ("resident_county", "12"),
            ("organ_donor", 0),
            ("name_suffix", "ESQ"),
        ],
    )
    def test_invalid_aamva_values(self, element, value):
        with pytest.raises(DocumentEncodingError, match=element):
            encode_document(
                MDL.doctype,
                {
                    "org.iso.18013.5.1": MDL_ELEMENTS,
                    "org.iso.18013.5.1.aamva": {**AAMVA_ELEMENTS, element: value},
                },
            )


class TestPhotoId:
    def test_encodes_both_namespaces(self):
        encoded = encode_document(
            PHOTO_ID.doctype,
            {
                "org.iso.23220.1": {**PHOTO_ID_CORE, "age_over_65": False, "sex": 2},
                "org.iso.23220.photoid.1": {
                    "person_id": "1234567890",
                    "birth_country": "CA",
                    "enrolment_portrait_image": PORTRAIT_B64,
                },
            },
        )
        core = decoded(encoded)["org.iso.23220.1"]
        assert core["birth_date"] == {
            "birth_date": date(1990, 4, 1),
            "approximate_mask": "00000011",
        }
        assert core["portrait"] == PORTRAIT
        assert core["issuing_country"] == "CAN"
        assert core["age_over_65"] is False
        photo = decoded(encoded)["org.iso.23220.photoid.1"]
        assert photo["enrolment_portrait_image"] == PORTRAIT

    def test_requires_core_namespace(self):
        with pytest.raises(DocumentEncodingError, match="org.iso.23220.1"):
            encode_document(
                PHOTO_ID.doctype, {"org.iso.23220.photoid.1": {"person_id": "1"}}
            )

    def test_age_over_18_is_mandatory(self):
        core = {k: v for k, v in PHOTO_ID_CORE.items() if k != "age_over_18"}
        with pytest.raises(DocumentEncodingError, match="age_over_18"):
            encode_document(PHOTO_ID.doctype, {"org.iso.23220.1": core})

    @pytest.mark.parametrize(
        "namespace, element, value",
        [
            ("org.iso.23220.1", "resident_country", "CAN"),
            ("org.iso.23220.1", "family_name", "x" * 151),
            ("org.iso.23220.1", "issuing_subdivision", "ON"),
            ("org.iso.23220.photoid.1", "birth_country", "CAN"),
            ("org.iso.23220.photoid.1", "resident_state", "東京都"),
        ],
    )
    def test_invalid_values(self, namespace, element, value):
        subject = {"org.iso.23220.1": dict(PHOTO_ID_CORE)}
        subject.setdefault(namespace, {})[element] = value
        with pytest.raises(DocumentEncodingError, match=element):
            encode_document(PHOTO_ID.doctype, subject)


class TestIssuerNamespaces:
    CLAIMS = {
        "ca.on.photoid.1": {
            "health_number": {"value_type": "tstr", "mandatory": True},
            "card_image": {"value_type": "bstr"},
            "registered_on": {"value_type": "full-date"},
            "updated_at": {"value_type": "tdate"},
            "visits": {"value_type": "uint"},
            "balance": {"value_type": "int"},
            "veteran": {"value_type": "bool"},
            "extra": {},
        }
    }

    def test_value_types(self):
        encoded = encode_document(
            PHOTO_ID.doctype,
            {
                "org.iso.23220.1": PHOTO_ID_CORE,
                "ca.on.photoid.1": {
                    "health_number": "1234-567-890",
                    "card_image": PORTRAIT_B64,
                    "registered_on": "2020-02-02",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "visits": 3,
                    "balance": -5,
                    "veteran": False,
                    "extra": {"nested": [1, "two"]},
                },
            },
            declared_claims(self.CLAIMS),
        )
        issuer = decoded(encoded)["ca.on.photoid.1"]
        assert issuer["card_image"] == PORTRAIT
        assert issuer["registered_on"] == date(2020, 2, 2)
        assert issuer["updated_at"] == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert issuer["extra"] == {"nested": [1, "two"]}

    def test_undeclared_namespace_or_element_is_refused(self):
        with pytest.raises(DocumentEncodingError, match="not declared"):
            encode_document(
                PHOTO_ID.doctype,
                {"org.iso.23220.1": PHOTO_ID_CORE, "ca.on.other.1": {"a": 1}},
                declared_claims(self.CLAIMS),
            )
        with pytest.raises(DocumentEncodingError, match="not declared"):
            encode_document(
                PHOTO_ID.doctype,
                {
                    "org.iso.23220.1": PHOTO_ID_CORE,
                    "ca.on.photoid.1": {"health_number": "1", "unknown": 1},
                },
                declared_claims(self.CLAIMS),
            )

    def test_mandatory_descriptor_is_enforced(self):
        with pytest.raises(DocumentEncodingError, match="health_number"):
            encode_document(
                PHOTO_ID.doctype,
                {"org.iso.23220.1": PHOTO_ID_CORE, "ca.on.photoid.1": {"visits": 1}},
                declared_claims(self.CLAIMS),
            )

    def test_claims_from_credential_metadata_paths(self):
        declared = declared_claims(
            None, [{"path": ["ca.on.photoid.1", "health_number"], "mandatory": True}]
        )
        encoded = encode_document(
            PHOTO_ID.doctype,
            {
                "org.iso.23220.1": PHOTO_ID_CORE,
                "ca.on.photoid.1": {"health_number": "1234"},
            },
            declared,
        )
        assert raw(encoded, "ca.on.photoid.1", "health_number") == "1234"


class TestClaimsConfig:
    def test_unknown_value_type(self):
        with pytest.raises(DocumentEncodingError, match="blob"):
            validate_claims_config({"ca.on.x.1": {"a": {"value_type": "blob"}}})

    def test_value_type_in_a_standard_namespace(self):
        with pytest.raises(DocumentEncodingError, match="issuer-defined"):
            validate_claims_config(
                {"org.iso.23220.1": {"family_name": {"value_type": "tstr"}}}
            )

    def test_unknown_standard_element(self):
        with pytest.raises(DocumentEncodingError, match="famly_name"):
            validate_claims_config({"org.iso.18013.5.1": {"famly_name": {}}})

    def test_valid_config(self):
        validate_claims_config(
            {
                "org.iso.18013.5.1": {
                    "family_name": {"mandatory": True},
                    "age_over_21": {},
                },
                "ca.on.x.1": {"a": {"value_type": "uint"}},
            }
        )


@pytest.mark.parametrize(
    "subject",
    [
        {"org.iso.23220.1": {**PHOTO_ID_CORE, "birth_date": "SECRET-1990"}},
        {"org.iso.23220.1": {**PHOTO_ID_CORE, "portrait": "SECRET!!portrait"}},
        {"org.iso.23220.1": {**PHOTO_ID_CORE, "family_name": "SECRET" * 30}},
    ],
)
def test_errors_never_contain_the_value(subject):
    with pytest.raises(DocumentEncodingError) as excinfo:
        encode_document(PHOTO_ID.doctype, subject)
    assert "SECRET" not in str(excinfo.value)


def test_dates_are_tagged_on_the_wire():
    """full-date is written as tag 1004 (d9 03ec) and tdate as tag 0 (c0)."""
    encoded = encode_document(
        PHOTO_ID.doctype,
        {
            "org.iso.23220.1": {
                **PHOTO_ID_CORE,
                "portrait_capture_date": "2025-12-01T10:00:00Z",
            }
        },
    )["org.iso.23220.1"]
    assert encoded["issue_date"] == bytes.fromhex("d903ec6a") + b"2026-01-01"
    assert encoded["portrait_capture_date"] == bytes.fromhex("c074") + (
        b"2025-12-01T10:00:00Z"
    )
