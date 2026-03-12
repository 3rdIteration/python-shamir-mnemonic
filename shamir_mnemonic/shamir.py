#
# Copyright (c) 2018 Andrew R. Kozlik
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

import hmac
import secrets
from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from . import cipher
from .constants import (
    DIGEST_INDEX,
    DIGEST_LENGTH_BYTES,
    GROUP_PREFIX_LENGTH_WORDS,
    ID_EXP_LENGTH_WORDS,
    ID_LENGTH_BITS,
    MAX_SHARE_COUNT,
    MIN_STRENGTH_BITS,
    SECRET_INDEX,
)
from .share import Share, ShareCommonParameters, ShareGroupParameters
from .utils import MnemonicError, bits_to_bytes


class RawShare(NamedTuple):
    x: int
    data: bytes


class ShareGroup:
    def __init__(self) -> None:
        self.shares: Set[Share] = set()

    def __iter__(self) -> Iterator[Share]:
        return iter(self.shares)

    def __len__(self) -> int:
        return len(self.shares)

    def __bool__(self) -> bool:
        return bool(self.shares)

    def __contains__(self, obj: Any) -> bool:
        return obj in self.shares

    def add(self, share: Share) -> None:
        if self.shares and self.group_parameters() != share.group_parameters():
            fields = zip(
                ShareGroupParameters._fields,
                self.group_parameters(),
                share.group_parameters(),
            )
            mismatch = next(name for name, x, y in fields if x != y)
            raise MnemonicError(
                f"Invalid set of mnemonics. The {mismatch} parameters don't match."
            )

        self.shares.add(share)

    def to_raw_shares(self) -> List[RawShare]:
        return [RawShare(s.index, s.value) for s in self.shares]

    def get_minimal_group(self) -> "ShareGroup":
        group = ShareGroup()
        group.shares = set(
            share for _, share in zip(range(self.member_threshold()), self.shares)
        )
        return group

    def common_parameters(self) -> ShareCommonParameters:
        return next(iter(self.shares)).common_parameters()

    def group_parameters(self) -> ShareGroupParameters:
        return next(iter(self.shares)).group_parameters()

    def member_threshold(self) -> int:
        return next(iter(self.shares)).member_threshold

    def is_complete(self) -> bool:
        if self.shares:
            return len(self.shares) >= self.member_threshold()
        else:
            return False


@dataclass(frozen=True)
class EncryptedMasterSecret:
    identifier: int
    extendable: bool
    iteration_exponent: int
    ciphertext: bytes

    @classmethod
    def from_master_secret(
        cls,
        master_secret: bytes,
        passphrase: bytes,
        identifier: int,
        extendable: bool,
        iteration_exponent: int,
    ) -> "EncryptedMasterSecret":
        ciphertext = cipher.encrypt(
            master_secret, passphrase, iteration_exponent, identifier, extendable
        )
        return EncryptedMasterSecret(
            identifier, extendable, iteration_exponent, ciphertext
        )

    def decrypt(self, passphrase: bytes) -> bytes:
        return cipher.decrypt(
            self.ciphertext,
            passphrase,
            self.iteration_exponent,
            self.identifier,
            self.extendable,
        )


RANDOM_BYTES = secrets.token_bytes
"""Source of random bytes. Can be overriden for deterministic testing."""


def _precompute_exp_log() -> Tuple[List[int], List[int]]:
    exp = [0 for i in range(255)]
    log = [0 for i in range(256)]

    poly = 1
    for i in range(255):
        exp[i] = poly
        log[poly] = i

        # Multiply poly by the polynomial x + 1.
        poly = (poly << 1) ^ poly

        # Reduce poly by x^8 + x^4 + x^3 + x + 1.
        if poly & 0x100:
            poly ^= 0x11B

    return exp, log


EXP_TABLE, LOG_TABLE = _precompute_exp_log()


def _interpolate(shares: Sequence[RawShare], x: int) -> bytes:
    """
    Returns f(x) given the Shamir shares (x_1, f(x_1)), ... , (x_k, f(x_k)).
    :param shares: The Shamir shares.
    :type shares: A list of pairs (x_i, y_i), where x_i is an integer and y_i is an array of
        bytes representing the evaluations of the polynomials in x_i.
    :param int x: The x coordinate of the result.
    :return: Evaluations of the polynomials in x.
    :rtype: Array of bytes.
    """

    x_coordinates = set(share.x for share in shares)

    if len(x_coordinates) != len(shares):
        raise MnemonicError("Invalid set of shares. Share indices must be unique.")

    share_value_lengths = set(len(share.data) for share in shares)
    if len(share_value_lengths) != 1:
        raise MnemonicError(
            "Invalid set of shares. All share values must have the same length."
        )

    if x in x_coordinates:
        for share in shares:
            if share.x == x:
                return share.data

    # Logarithm of the product of (x_i - x) for i = 1, ... , k.
    log_prod = sum(LOG_TABLE[share.x ^ x] for share in shares)

    result = bytes(share_value_lengths.pop())
    for share in shares:
        # The logarithm of the Lagrange basis polynomial evaluated at x.
        log_basis_eval = (
            log_prod
            - LOG_TABLE[share.x ^ x]
            - sum(LOG_TABLE[share.x ^ other.x] for other in shares)
        ) % 255

        result = bytes(
            intermediate_sum
            ^ (
                EXP_TABLE[(LOG_TABLE[share_val] + log_basis_eval) % 255]
                if share_val != 0
                else 0
            )
            for share_val, intermediate_sum in zip(share.data, result)
        )

    return result


def _create_digest(random_data: bytes, shared_secret: bytes) -> bytes:
    return hmac.new(random_data, shared_secret, "sha256").digest()[:DIGEST_LENGTH_BYTES]


def _split_secret(
    threshold: int, share_count: int, shared_secret: bytes
) -> List[RawShare]:
    if threshold < 1:
        raise ValueError("The requested threshold must be a positive integer.")

    if threshold > share_count:
        raise ValueError(
            "The requested threshold must not exceed the number of shares."
        )

    if share_count > MAX_SHARE_COUNT:
        raise ValueError(
            f"The requested number of shares must not exceed {MAX_SHARE_COUNT}."
        )

    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return [RawShare(i, shared_secret) for i in range(share_count)]

    random_share_count = threshold - 2

    shares = [
        RawShare(i, RANDOM_BYTES(len(shared_secret))) for i in range(random_share_count)
    ]

    random_part = RANDOM_BYTES(len(shared_secret) - DIGEST_LENGTH_BYTES)
    digest = _create_digest(random_part, shared_secret)

    base_shares = shares + [
        RawShare(DIGEST_INDEX, digest + random_part),
        RawShare(SECRET_INDEX, shared_secret),
    ]

    for i in range(random_share_count, share_count):
        shares.append(RawShare(i, _interpolate(base_shares, i)))

    return shares


def _recover_secret(threshold: int, shares: Sequence[RawShare]) -> bytes:
    # If the threshold is 1, then the digest of the shared secret is not used.
    if threshold == 1:
        return next(iter(shares)).data

    shared_secret = _interpolate(shares, SECRET_INDEX)
    digest_share = _interpolate(shares, DIGEST_INDEX)
    digest = digest_share[:DIGEST_LENGTH_BYTES]
    random_part = digest_share[DIGEST_LENGTH_BYTES:]

    if digest != _create_digest(random_part, shared_secret):
        raise MnemonicError("Invalid digest of the shared secret.")

    return shared_secret


def decode_mnemonics(mnemonics: Iterable[str]) -> Dict[int, ShareGroup]:
    common_params: Set[ShareCommonParameters] = set()
    groups: Dict[int, ShareGroup] = {}
    for mnemonic in mnemonics:
        share = Share.from_mnemonic(mnemonic)
        common_params.add(share.common_parameters())
        group = groups.setdefault(share.group_index, ShareGroup())
        group.add(share)

    if len(common_params) != 1:
        raise MnemonicError(
            "Invalid set of mnemonics. "
            f"All mnemonics must begin with the same {ID_EXP_LENGTH_WORDS} words, "
            "must have the same group threshold and the same group count."
        )

    return groups


def split_ems(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    encrypted_master_secret: EncryptedMasterSecret,
) -> List[List[Share]]:
    """
    Split an Encrypted Master Secret into mnemonic shares.

    This function is a counterpart to `recover_ems`, and it is used as a subroutine in
    `generate_mnemonics`. The input is an *already encrypted* Master Secret (EMS), so it
    is possible to encrypt the Master Secret in advance and perform the splitting later.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param encrypted_master_secret: The encrypted master secret to split.
    :return: List of groups of mnemonics.
    """
    if len(encrypted_master_secret.ciphertext) * 8 < MIN_STRENGTH_BITS:
        raise ValueError(
            "The length of the master secret must be "
            f"at least {bits_to_bytes(MIN_STRENGTH_BITS)} bytes."
        )

    if group_threshold > len(groups):
        raise ValueError(
            "The requested group threshold must not exceed the number of groups."
        )

    if any(
        member_threshold == 1 and member_count > 1
        for member_threshold, member_count in groups
    ):
        raise ValueError(
            "Creating multiple member shares with member threshold 1 is not allowed. "
            "Use 1-of-1 member sharing instead."
        )

    group_shares = _split_secret(
        group_threshold, len(groups), encrypted_master_secret.ciphertext
    )

    return [
        [
            Share(
                encrypted_master_secret.identifier,
                encrypted_master_secret.extendable,
                encrypted_master_secret.iteration_exponent,
                group_index,
                group_threshold,
                len(groups),
                member_index,
                member_threshold,
                value,
            )
            for member_index, value in _split_secret(
                member_threshold, member_count, group_secret
            )
        ]
        for (member_threshold, member_count), (group_index, group_secret) in zip(
            groups, group_shares
        )
    ]


def _random_identifier() -> int:
    """Returns a random identifier with the given bit length."""
    identifier = int.from_bytes(RANDOM_BYTES(bits_to_bytes(ID_LENGTH_BITS)), "big")
    return identifier & ((1 << ID_LENGTH_BITS) - 1)


def generate_mnemonics(
    group_threshold: int,
    groups: Sequence[Tuple[int, int]],
    master_secret: bytes,
    passphrase: bytes = b"",
    extendable: bool = True,
    iteration_exponent: int = 1,
) -> List[List[str]]:
    """
    Split a master secret into mnemonic shares using Shamir's secret sharing scheme.

    The supplied Master Secret is encrypted by the passphrase (empty passphrase is used
    if none is provided) and split into a set of mnemonic shares.

    This is the user-friendly method to back up a pre-existing secret with the Shamir
    scheme, optionally protected by a passphrase.

    :param group_threshold: The number of groups required to reconstruct the master secret.
    :param groups: A list of (member_threshold, member_count) pairs for each group, where member_count
        is the number of shares to generate for the group and member_threshold is the number of members required to
        reconstruct the group secret.
    :param master_secret: The master secret to split.
    :param passphrase: The passphrase used to encrypt the master secret.
    :param int iteration_exponent: The encryption iteration exponent.
    :return: List of groups mnemonics.
    """
    if not all(32 <= c <= 126 for c in passphrase):
        raise ValueError(
            "The passphrase must contain only printable ASCII characters (code points 32-126)."
        )

    identifier = _random_identifier()
    encrypted_master_secret = EncryptedMasterSecret.from_master_secret(
        master_secret, passphrase, identifier, extendable, iteration_exponent
    )
    grouped_shares = split_ems(group_threshold, groups, encrypted_master_secret)
    return [[share.mnemonic() for share in group] for group in grouped_shares]


def recover_ems(groups: Dict[int, ShareGroup]) -> EncryptedMasterSecret:
    """
    Combine shares, recover metadata and the Encrypted Master Secret.

    This function is a counterpart to `split_ems`, and it is used as a subroutine in
    `combine_mnemonics`. It returns the EMS itself and data required for its decryption,
    except for the passphrase. It is thus possible to defer decryption of the Master
    Secret to a later time.

    :param groups: Set of shares classified into groups.
    :return: Encrypted Master Secret
    """

    if not groups:
        raise MnemonicError("The set of shares is empty.")

    params = next(iter(groups.values())).common_parameters()

    if len(groups) < params.group_threshold:
        raise MnemonicError(
            "Insufficient number of mnemonic groups. "
            f"The required number of groups is {params.group_threshold}."
        )

    if len(groups) != params.group_threshold:
        raise MnemonicError(
            "Wrong number of mnemonic groups. "
            f"Expected {params.group_threshold} groups, "
            f"but {len(groups)} were provided."
        )

    for group in groups.values():
        if len(group) != group.member_threshold():
            share_words = next(iter(group)).words()
            prefix = " ".join(share_words[:GROUP_PREFIX_LENGTH_WORDS])
            raise MnemonicError(
                "Wrong number of mnemonics. "
                f'Expected {group.member_threshold()} mnemonics starting with "{prefix} ...", '
                f"but {len(group)} were provided."
            )

    group_shares = [
        RawShare(
            group_index,
            _recover_secret(group.member_threshold(), group.to_raw_shares()),
        )
        for group_index, group in groups.items()
    ]

    ciphertext = _recover_secret(params.group_threshold, group_shares)
    return EncryptedMasterSecret(
        params.identifier, params.extendable, params.iteration_exponent, ciphertext
    )


def combine_mnemonics(mnemonics: Iterable[str], passphrase: bytes = b"") -> bytes:
    """
    Combine mnemonic shares to obtain the master secret which was previously split
    using Shamir's secret sharing scheme.

    This is the user-friendly method to recover a backed-up secret optionally protected
    by a passphrase.

    :param mnemonics: List of mnemonics.
    :param passphrase: The passphrase used to encrypt the master secret.
    :return: The master secret.
    """

    if not mnemonics:
        raise MnemonicError("The list of mnemonics is empty.")

    groups = decode_mnemonics(mnemonics)
    encrypted_master_secret = recover_ems(groups)
    return encrypted_master_secret.decrypt(passphrase)


def verify_mnemonics(
    mnemonics: Iterable[str],
    passphrase: bytes,
    expected_master_secret: bytes,
) -> None:
    """
    Verify that mnemonic shares were encrypted correctly according to their
    declared parameters (identifier, extendable flag, iteration exponent).

    This function detects shares that were created with mismatched encryption
    parameters -- for example, shares flagged as non-extendable but encrypted
    with an empty salt (as if extendable). Such a mismatch breaks the security
    guarantee of non-extendable shares, making them reworkable despite being
    marked otherwise.

    :param mnemonics: List of mnemonics.
    :param passphrase: The passphrase used to encrypt the master secret.
    :param expected_master_secret: The known-correct master secret to verify against.
    :raises MnemonicError: If the shares have a salt/extendable flag mismatch or
        do not match the expected master secret.
    """

    if not mnemonics:
        raise MnemonicError("The list of mnemonics is empty.")

    groups = decode_mnemonics(mnemonics)
    ems = recover_ems(groups)

    # Decrypt using the declared parameters from the share metadata.
    decrypted = ems.decrypt(passphrase)

    if decrypted == expected_master_secret:
        return

    # The declared parameters did not produce the expected master secret.
    # Try decrypting with the opposite extendable flag to diagnose a
    # specific salt mismatch (e.g. non-extendable flag but empty salt).
    alt_ems = EncryptedMasterSecret(
        ems.identifier, not ems.extendable, ems.iteration_exponent, ems.ciphertext
    )
    alt_decrypted = alt_ems.decrypt(passphrase)

    if alt_decrypted == expected_master_secret:
        if ems.extendable:
            raise MnemonicError(
                "Share extendable flag mismatch: shares are flagged as extendable "
                "but were encrypted with the non-extendable salt "
                "(customization string + identifier). "
                "The shares will not be interoperable with compliant implementations."
            )
        else:
            raise MnemonicError(
                "Share extendable flag mismatch: shares are flagged as non-extendable "
                "but were encrypted with an empty salt (extendable mode). "
                "This means the non-extendable security property is not enforced -- "
                "the shares are effectively reworkable despite being marked otherwise."
            )

    raise MnemonicError(
        "The shares do not match the expected master secret with either "
        "extendable or non-extendable encryption parameters."
    )


@dataclass(frozen=True)
class EraImportResult:
    """Diagnostic result from simulating ERA wallet's SLIP39 import path.

    ERA wallet (ERAWLT/ERA-crypto-p) has two bugs in its SLIP39 handling:

    Bug 1 — Passphrase ignored during import:
      ``decodeShamirShares()`` and ``addAccount()`` always call
      ``encryptedMasterSecret.decrypt("")`` regardless of any user passphrase,
      so the stored "entropy" is wrong for passphrase-protected shares.
      https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L210
      https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L433

    Bug 2 — extendable flag hardcoded False during re-encryption:
      The ``Account`` constructor always calls
      ``EncryptedMasterSecret::fromMasterSecret(entropy, "", id, false, ie)``
      with ``extendable=false`` when re-encrypting for storage.
      https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L850-L851

    Due to the Feistel cipher round-trip property
    ``encrypt(decrypt(ct, S), S) = ct``, when the same (empty) passphrase and
    same salt are used for both decrypt and re-encrypt, the original ciphertext
    is paradoxically preserved. This means the stored EMS is often identical to
    the original, and entering the correct passphrase later may still produce
    correct keys. However, the stored *entropy* is wrong.
    """

    stored_entropy: bytes
    """What ERA stores as the account's entropy — wrong for passphrase-protected shares."""

    stored_ems: bytes
    """The EMS ciphertext ERA stores. Identical to the original when id/ie are preserved."""

    identifier: int
    """The SLIP39 identifier from the original shares."""

    iteration_exponent: int
    """The iteration exponent from the original shares."""

    extendable: bool
    """The extendable flag from the original shares."""

    no_passphrase_seed: bytes
    """The seed ERA derives for the no-passphrase wallet (may be wrong)."""

    passphrase_seed: bytes
    """The seed ERA derives when user enters the passphrase."""

    correct_master_secret: bytes
    """What a compliant implementation would recover with the same passphrase."""


def simulate_era_import(
    mnemonics: Iterable[str],
    passphrase: bytes = b"",
) -> EraImportResult:
    """Simulate ERA wallet's SLIP39 import path and return diagnostic info.

    This function models the exact code path in the ERA wallet
    (``ERAWLT/ERA-crypto-p``,
    `Account.cpp <https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp>`_)
    when SLIP39 shares are imported:

    1. ``decodeShamirShares`` / ``addAccount`` recover the EMS from shares.
    2. ERA decrypts the EMS with an **empty** passphrase (Bug 1) to obtain
       the "entropy" it stores internally.
    3. ERA re-encrypts the stored entropy with ``extendable=false`` (Bug 2)
       and the original identifier/iteration-exponent to produce a new EMS
       for storage.
    4. For the no-passphrase wallet, ERA decrypts the stored EMS with ``""``.
    5. When the user enters a passphrase, ERA decrypts the stored EMS with
       that passphrase — this step uses ``extendable=false`` unconditionally.

    :param mnemonics: SLIP39 mnemonic shares (enough to meet the threshold).
    :param passphrase: The passphrase the user would enter in ERA wallet.
    :return: An :class:`EraImportResult` with all intermediate values.
    """
    groups = decode_mnemonics(mnemonics)
    ems = recover_ems(groups)

    # Bug 1: ERA always decrypts with empty passphrase.
    era_entropy = cipher.decrypt(
        ems.ciphertext, b"", ems.iteration_exponent, ems.identifier, ems.extendable
    )

    # Bug 2: ERA re-encrypts with extendable=False (hardcoded), empty passphrase.
    era_ems = cipher.encrypt(
        era_entropy,
        b"",
        ems.iteration_exponent,
        ems.identifier,
        False,  # ERA always uses extendable=False
    )

    # ERA's no-passphrase seed: decrypt(stored_ems, "", ie, id, False)
    no_pp_seed = cipher.decrypt(
        era_ems, b"", ems.iteration_exponent, ems.identifier, False
    )

    # ERA's passphrase seed: decrypt(stored_ems, passphrase, ie, id, False)
    pp_seed = cipher.decrypt(
        era_ems, passphrase, ems.iteration_exponent, ems.identifier, False
    )

    # What a compliant implementation would get.
    correct_ms = ems.decrypt(passphrase)

    return EraImportResult(
        stored_entropy=era_entropy,
        stored_ems=era_ems,
        identifier=ems.identifier,
        iteration_exponent=ems.iteration_exponent,
        extendable=ems.extendable,
        no_passphrase_seed=no_pp_seed,
        passphrase_seed=pp_seed,
        correct_master_secret=correct_ms,
    )


@dataclass(frozen=True)
class EraReworkResult:
    """Diagnostic result from simulating ERA wallet's SLIP39 rework (backup regeneration).

    When the ERA wallet regenerates SLIP39 shares (e.g. to change threshold or
    share count), it follows this path (``CryptoModule::createMnemonic`` →
    ``AccountsManager::generateMnemonicSLIP39``):

    1. Read the stored entropy from the account's ``AccountSecureData``.
    2. Call ``generateMnemonics(1, groups, entropy, "", identifier, false, ie)``
       with the stored identifier from ``getSlip39Identifier()`` and stored
       iteration exponent from ``getSlip39IterationExponent()``.

    **There is no validation or blocking** in the ERA wallet code to prevent
    rework of passphrase-protected shares.  The code does not:
    - Check whether the stored entropy was derived with a passphrase
    - Warn the user that rework with wrong entropy will produce bad shares
    - Preserve the original EMS ciphertext during rework

    The ``createMnemonic`` function receives the identifier and iteration
    exponent from ``CryptoModule::getAccountSlip39Identifier()`` and
    ``CryptoModule::getAccountSlip39IterationExponent()``.  If the account
    has no active session (``_getActiveAccount({})`` returns null), these
    functions return **0**, which means a different (zero) identifier could
    be used silently — breaking the Feistel round-trip property.
    """

    original_identifier: int
    """The SLIP39 identifier from the original shares."""

    rework_identifier: int
    """The identifier used during rework (may differ if account session is lost)."""

    stored_entropy: bytes
    """What ERA stored as entropy (wrong for passphrase-protected shares)."""

    reworked_ems: bytes
    """The EMS ciphertext in the reworked shares."""

    reworked_shares: List[str]
    """The mnemonic shares produced by the rework."""

    recovered_with_passphrase: bytes
    """What a compliant tool recovers from reworked shares WITH the original passphrase."""

    recovered_without_passphrase: bytes
    """What a compliant tool recovers from reworked shares WITHOUT passphrase."""

    original_secret_recoverable: bool
    """Whether the original master secret can be recovered from the reworked shares."""


def simulate_era_rework(
    mnemonics: Iterable[str],
    passphrase: bytes = b"",
    rework_groups: Sequence[Tuple[int, int]] = ((2, 3),),
    new_identifier: Optional[int] = None,
) -> EraReworkResult:
    """Simulate ERA wallet's SLIP39 rework (backup regeneration) path.

    This models what happens when the ERA wallet regenerates SLIP39 shares
    from stored account data.  The ERA code path is:

    ``CryptoModule::createMnemonic`` → ``AccountsManager::generateMnemonicSLIP39``
    → ``ShamirMnemonic::generateMnemonics(1, groups, entropy, "", id, false, ie)``

    The entropy comes from ``AccountSecureData::entropy``, which was stored
    during import by decrypting the EMS with an empty passphrase (Bug 1).

    The identifier comes from ``CryptoModule::getAccountSlip39Identifier()``,
    which reads ``AccountSecureData::slip39Id``.  However, if the active
    account session is not available, it returns **0** — a different value.

    **ERA has NO code to block this rework path for passphrase-protected shares.**
    Specifically:

    - `generateMnemonicSLIP39 <https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L102-L127>`_
      (Account.cpp:102-127) takes entropy and
      identifier as parameters and calls ``generateMnemonics`` with
      ``extendable=false`` and an **empty passphrase** unconditionally.
    - There is no check for whether the entropy was originally passphrase-protected.
    - There is no warning or error when reworking passphrase-protected shares.
    - The `createMnemonic <https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp#L394-L408>`_
      API (CryptoModule.cpp:394-408) simply forwards
      parameters without validation.

    :param mnemonics: Original SLIP39 mnemonic shares.
    :param passphrase: The original passphrase used to create the shares.
    :param rework_groups: The new group scheme for reworked shares.
    :param new_identifier: If set, use this identifier for rework (simulates
        the case where ``getAccountSlip39Identifier()`` returns a different
        value, e.g. 0).  If None, use the original identifier.
    :return: An :class:`EraReworkResult` with diagnostic info.
    """
    # Step 1: Import into ERA (to get the stored entropy).
    import_result = simulate_era_import(mnemonics, passphrase)

    rework_id = (
        new_identifier if new_identifier is not None else import_result.identifier
    )
    ie = import_result.iteration_exponent

    # Step 2: ERA calls generateMnemonicSLIP39(entropy, "", id, false, ie)
    # This is Account.cpp line 113:
    #   generateMnemonics(1, groups, entropy, "", identifier, false, iterationExponent)
    reworked_ems_obj = EncryptedMasterSecret.from_master_secret(
        import_result.stored_entropy,
        b"",  # ERA always uses empty passphrase
        rework_id,
        False,  # ERA hardcodes extendable=False
        ie,
    )

    grouped_shares = split_ems(1, list(rework_groups), reworked_ems_obj)
    reworked_mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    # Step 3: What does a compliant tool get from these reworked shares?
    threshold = rework_groups[0][0]
    recovered_with_pp = combine_mnemonics(reworked_mnemonics[:threshold], passphrase)
    recovered_without_pp = combine_mnemonics(reworked_mnemonics[:threshold])

    correct_ms = import_result.correct_master_secret
    recoverable = recovered_with_pp == correct_ms or recovered_without_pp == correct_ms

    return EraReworkResult(
        original_identifier=import_result.identifier,
        rework_identifier=rework_id,
        stored_entropy=import_result.stored_entropy,
        reworked_ems=reworked_ems_obj.ciphertext,
        reworked_shares=reworked_mnemonics,
        recovered_with_passphrase=recovered_with_pp,
        recovered_without_passphrase=recovered_without_pp,
        original_secret_recoverable=recoverable,
    )
