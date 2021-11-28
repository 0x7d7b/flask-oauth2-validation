from typing import Tuple
from jwt.jwk import RSAJWK
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import JWT


def _generate_test_keys() -> Tuple[rsa.RSAPublicKey, rsa.RSAPrivateKey]:
    private_key: rsa.RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return public_key, private_key


def _generate_test_jwk(public_key: rsa.RSAPublicKey) -> dict:
    jwk = RSAJWK(public_key, kid='a', alg='RS256')
    return jwk.to_dict(public_only=True)


_public_key, _private_key = _generate_test_keys()
_jwt = JWT()


test_jwk = _generate_test_jwk(_public_key)


def generate_test_token(
    payload: dict,
    optional_headers={'kid': 'a'},
    key=RSAJWK(_private_key, kid='a', alg='RS256')
) -> str:
    return _jwt.encode(
        payload=payload,
        key=key,
        alg='RS256',
        optional_headers=optional_headers
    )


mocked_keys = {
    'x': {'kid': 'x'},
    'a': test_jwk,
    'z': {'kid': 'z'}
}
