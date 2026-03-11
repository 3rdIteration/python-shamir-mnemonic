import hashlib

from .constants import (
    BASE_ITERATION_COUNT,
    CUSTOMIZATION_STRING_ORIG,
    ID_LENGTH_BITS,
    ROUND_COUNT,
)
from .utils import bits_to_bytes


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _round_function(i: int, passphrase: bytes, e: int, salt: bytes, r: bytes) -> bytes:
    """The round function used internally by the Feistel cipher."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        bytes([i]) + passphrase,
        salt + r,
        (BASE_ITERATION_COUNT << e) // ROUND_COUNT,
        dklen=len(r),
    )


def _get_salt(identifier: int, extendable: bool) -> bytes:
    """Return the salt for the Feistel cipher round function.

    :param identifier: The random identifier for the set of shares.
    :param extendable: If True, the salt is empty. If False, the salt includes the
        identifier.

    For extendable shares, the salt is empty. For non-extendable shares, the salt
    includes the identifier, which means that re-generating shares (with a new random
    identifier) for the same master secret will produce a different encrypted form.
    As a result, recovering non-extendable shares with a wrong passphrase will yield
    different incorrect secrets for each generation, whereas extendable shares will
    always yield the same result for any given passphrase.
    """
    if extendable:
        return bytes()
    identifier_len = bits_to_bytes(ID_LENGTH_BITS)
    return CUSTOMIZATION_STRING_ORIG + identifier.to_bytes(identifier_len, "big")


def encrypt(
    master_secret: bytes,
    passphrase: bytes,
    iteration_exponent: int,
    identifier: int,
    extendable: bool,
) -> bytes:
    if len(master_secret) % 2 != 0:
        raise ValueError(
            "The length of the master secret in bytes must be an even number."
        )

    l = master_secret[: len(master_secret) // 2]
    r = master_secret[len(master_secret) // 2 :]
    salt = _get_salt(identifier, extendable)
    for i in range(ROUND_COUNT):
        f = _round_function(i, passphrase, iteration_exponent, salt, r)
        l, r = r, _xor(l, f)
    return r + l


def decrypt(
    encrypted_master_secret: bytes,
    passphrase: bytes,
    iteration_exponent: int,
    identifier: int,
    extendable: bool,
) -> bytes:
    if len(encrypted_master_secret) % 2 != 0:
        raise ValueError(
            "The length of the encrypted master secret in bytes must be an even number."
        )

    l = encrypted_master_secret[: len(encrypted_master_secret) // 2]
    r = encrypted_master_secret[len(encrypted_master_secret) // 2 :]
    salt = _get_salt(identifier, extendable)
    for i in reversed(range(ROUND_COUNT)):
        f = _round_function(i, passphrase, iteration_exponent, salt, r)
        l, r = r, _xor(l, f)
    return r + l
