import pytest

from oid4vc.jose_util import JoseError, jwk_thumbprint, verify_jws

from .jose_helpers import ec_key, ed_key, public_jwk, rsa_key, sign


@pytest.mark.parametrize(
    "key_factory, alg",
    [(rsa_key, "RS256"), (rsa_key, "PS256"), (ec_key, "ES256"), (ed_key, "EdDSA")],
)
def test_verify_jws_roundtrip(key_factory, alg):
    key = key_factory()
    token = sign({"typ": "JWT"}, {"hello": "world"}, key, alg)
    header, payload = verify_jws(token, public_jwk(key))
    assert header["alg"] == alg
    assert payload == {"hello": "world"}


def test_verify_jws_wrong_key():
    token = sign({}, {"a": 1}, ec_key(), "ES256")
    with pytest.raises(JoseError):
        verify_jws(token, public_jwk(ec_key()))


def test_verify_jws_rejects_symmetric_and_none():
    key = ec_key()
    token = sign({}, {"a": 1}, key, "ES256")
    head, body, sig = token.split(".")
    from oid4vc.jose_util import b64url_encode

    for alg in ("HS256", "none"):
        forged_head = b64url_encode(f'{{"alg":"{alg}"}}'.encode())
        with pytest.raises(JoseError):
            verify_jws(f"{forged_head}.{body}.{sig}", public_jwk(key))


def test_verify_jws_alg_key_mismatch():
    key = rsa_key()
    token = sign({}, {"a": 1}, key, "RS256")
    with pytest.raises(JoseError):
        verify_jws(token, public_jwk(ec_key()))


def test_thumbprint_ignores_order_and_extra_members():
    jwk = public_jwk(ec_key())
    reordered = {k: jwk[k] for k in reversed(list(jwk))}
    assert jwk_thumbprint(jwk) == jwk_thumbprint({**reordered, "kid": "x", "use": "sig"})


def test_thumbprint_rfc7638_example():
    # RFC 7638 §3.1
    jwk = {
        "kty": "RSA",
        "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert jwk_thumbprint(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
