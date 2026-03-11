import json
import secrets
from itertools import combinations
from random import shuffle

import pytest
from bip32utils import BIP32Key

import shamir_mnemonic as shamir
from shamir_mnemonic import MnemonicError

MS = b"ABCDEFGHIJKLMNOP"


def test_basic_sharing_random():
    secret = secrets.token_bytes(16)
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], secret)[0]
    assert shamir.combine_mnemonics(mnemonics[:3]) == shamir.combine_mnemonics(
        mnemonics[2:]
    )


def test_basic_sharing_fixed():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[:3])
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[1:3])


def test_passphrase():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_non_extendable():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, extendable=False)[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4])


def test_non_extendable_regeneration_passphrase_inconsistency():
    """Non-extendable shares: regenerating shares for the same master secret produces
    different results when combined with a wrong passphrase, because the random
    identifier is included in the encryption salt.

    With the correct passphrase, both sets recover the original master secret.
    With a wrong passphrase, each set produces a different (incorrect) secret.
    """
    mnemonics1 = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=False
    )[0]
    mnemonics2 = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=False
    )[0]

    # Correct passphrase: both sets recover the same master secret.
    assert MS == shamir.combine_mnemonics(mnemonics1[:3], b"TREZOR")
    assert MS == shamir.combine_mnemonics(mnemonics2[:3], b"TREZOR")

    # Wrong (empty) passphrase: each set produces a different incorrect secret,
    # because the identifier differs between the two generations and is part of
    # the encryption salt for non-extendable shares.
    wrong_pw_result1 = shamir.combine_mnemonics(mnemonics1[:3])
    wrong_pw_result2 = shamir.combine_mnemonics(mnemonics2[:3])
    assert wrong_pw_result1 != MS
    assert wrong_pw_result2 != MS
    assert wrong_pw_result1 != wrong_pw_result2


def test_extendable_regeneration_passphrase_consistency():
    """Extendable shares: regenerating shares for the same master secret produces
    the same results even when combined with a wrong passphrase, because the
    encryption salt does not include the identifier.

    This is the key advantage of extendable (reworkable) shares over non-extendable
    (non-reworkable) ones: the derived secret is always consistent regardless of which
    set of shares is used, for any passphrase.
    """
    mnemonics1 = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=True)[
        0
    ]
    mnemonics2 = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=True)[
        0
    ]

    # Correct passphrase: both sets recover the same master secret.
    assert MS == shamir.combine_mnemonics(mnemonics1[:3], b"TREZOR")
    assert MS == shamir.combine_mnemonics(mnemonics2[:3], b"TREZOR")

    # Wrong (empty) passphrase: both sets produce the same (incorrect) secret,
    # because the encryption salt is empty for extendable shares and does not
    # depend on the identifier.
    wrong_pw_result1 = shamir.combine_mnemonics(mnemonics1[:3])
    wrong_pw_result2 = shamir.combine_mnemonics(mnemonics2[:3])
    assert wrong_pw_result1 != MS
    assert wrong_pw_result2 != MS
    assert wrong_pw_result1 == wrong_pw_result2


def test_iteration_exponent():
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=1
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", iteration_exponent=2
    )[0]
    assert MS == shamir.combine_mnemonics(mnemonics[1:4], b"TREZOR")
    assert MS != shamir.combine_mnemonics(mnemonics[1:4])


def test_group_sharing():
    group_threshold = 2
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for groups in combinations(zip(mnemonics, member_thresholds), group_threshold):
        for group1_subset in combinations(groups[0][0], groups[0][1]):
            for group2_subset in combinations(groups[1][0], groups[1][1]):
                mnemonic_subset = list(group1_subset + group2_subset)
                shuffle(mnemonic_subset)
                assert MS == shamir.combine_mnemonics(mnemonic_subset)

    # Minimal sets of mnemonics.
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][0], mnemonics[2][2], mnemonics[3][0]]
    )
    assert MS == shamir.combine_mnemonics(
        [mnemonics[2][3], mnemonics[3][0], mnemonics[2][4]]
    )

    # One complete group and one incomplete group out of two groups required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][2:] + [mnemonics[1][0]])

    # One group of two required.
    with pytest.raises(MnemonicError):
        shamir.combine_mnemonics(mnemonics[0][1:4])


def test_group_sharing_threshold_1():
    group_threshold = 1
    group_sizes = (5, 3, 5, 1)
    member_thresholds = (3, 2, 2, 1)
    mnemonics = shamir.generate_mnemonics(
        group_threshold, list(zip(member_thresholds, group_sizes)), MS
    )

    # Test all valid combinations of mnemonics.
    for group, member_threshold in zip(mnemonics, member_thresholds):
        for group_subset in combinations(group, member_threshold):
            mnemonic_subset = list(group_subset)
            shuffle(mnemonic_subset)
            assert MS == shamir.combine_mnemonics(mnemonic_subset)


def test_all_groups_exist():
    for group_threshold in (1, 2, 5):
        mnemonics = shamir.generate_mnemonics(
            group_threshold, [(3, 5), (1, 1), (2, 3), (2, 5), (3, 5)], MS
        )
        assert len(mnemonics) == 5
        assert len(sum(mnemonics, [])) == 19


def test_invalid_sharing():
    # Short master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS[:14])

    # Odd length master secret.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(1, [(2, 3)], MS + b"X")

    # Group threshold exceeds number of groups.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(3, [(3, 5), (2, 5)], MS)

    # Invalid group threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(0, [(3, 5), (2, 5)], MS)

    # Member threshold exceeds number of members.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 2), (2, 5)], MS)

    # Invalid member threshold.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(0, 2), (2, 5)], MS)

    # Group with multiple members and member threshold 1.
    with pytest.raises(ValueError):
        shamir.generate_mnemonics(2, [(3, 5), (1, 3), (2, 5)], MS)


def test_vectors():
    with open("vectors.json", "r") as f:
        vectors = json.load(f)
    for description, mnemonics, secret_hex, xprv in vectors:
        if secret_hex:
            secret = bytes.fromhex(secret_hex)
            assert secret == shamir.combine_mnemonics(
                mnemonics, b"TREZOR"
            ), 'Incorrect secret for test vector "{}".'.format(description)
            assert (
                BIP32Key.fromEntropy(secret).ExtendedKey() == xprv
            ), 'Incorrect xprv for test vector "{}".'.format(description)
        else:
            with pytest.raises(MnemonicError):
                shamir.combine_mnemonics(mnemonics)
                pytest.fail(
                    'Failed to raise exception for test vector "{}".'.format(
                        description
                    )
                )


def test_split_ems():
    encrypted_master_secret = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"TREZOR", identifier=42, extendable=True, iteration_exponent=1
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], encrypted_master_secret)
    mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    recovered = shamir.combine_mnemonics(mnemonics[:3], b"TREZOR")
    assert recovered == MS


def test_recover_ems():
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]

    groups = shamir.decode_mnemonics(mnemonics[:3])
    encrypted_master_secret = shamir.recover_ems(groups)
    recovered = encrypted_master_secret.decrypt(b"TREZOR")
    assert recovered == MS


def test_resplit_non_extendable():
    """Non-extendable shares can be safely re-split when the identifier is preserved.

    Because resplit_mnemonics recovers the EMS (which includes the original identifier)
    and re-splits it, the encryption salt stays the same, and the new shares decrypt to
    the same master secret with any passphrase.
    """
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]

    # Re-split into a different group configuration.
    new_shares = shamir.resplit_mnemonics(original[:3], 1, [(2, 3)])

    # New shares recover the same master secret with the correct passphrase.
    assert MS == shamir.combine_mnemonics(new_shares[0][:2], b"TREZOR")


def test_resplit_extendable():
    """Extendable shares can also be re-split."""
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=True)[0]

    new_shares = shamir.resplit_mnemonics(original[:3], 1, [(2, 3)])
    assert MS == shamir.combine_mnemonics(new_shares[0][:2], b"TREZOR")


def test_resplit_non_extendable_wrong_passphrase_consistency():
    """After re-splitting non-extendable shares (preserving identifier), the new shares
    produce the same result as the original shares for any passphrase, including a wrong
    one. This is because the identifier (and therefore the encryption salt) is preserved.
    """
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]

    new_shares = shamir.resplit_mnemonics(original[:3], 1, [(2, 3)])

    # Correct passphrase: both yield the original master secret.
    assert MS == shamir.combine_mnemonics(original[:3], b"TREZOR")
    assert MS == shamir.combine_mnemonics(new_shares[0][:2], b"TREZOR")

    # Wrong (empty) passphrase: both yield the same (incorrect) secret,
    # because the identifier and salt are preserved.
    wrong_pw_original = shamir.combine_mnemonics(original[:3])
    wrong_pw_new = shamir.combine_mnemonics(new_shares[0][:2])
    assert wrong_pw_original != MS
    assert wrong_pw_new != MS
    assert wrong_pw_original == wrong_pw_new


def test_resplit_non_extendable_different_group_structure():
    """Re-splitting non-extendable shares into a more complex group structure works
    correctly and preserves decryption consistency.
    """
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]

    # Re-split into 2-of-3 groups with different member thresholds.
    new_shares = shamir.resplit_mnemonics(original[:3], 2, [(2, 3), (3, 5), (1, 1)])

    # Recover using group 0 + group 2.
    assert MS == shamir.combine_mnemonics(
        new_shares[0][:2] + new_shares[2][:1], b"TREZOR"
    )

    # Recover using group 1 + group 2.
    assert MS == shamir.combine_mnemonics(
        new_shares[1][:3] + new_shares[2][:1], b"TREZOR"
    )


def test_rework_non_extendable_to_extendable():
    """Non-extendable shares can be reworked to extendable given the passphrase.

    This demonstrates that the non-extendable flag is a software convention, not
    a cryptographic guarantee: with the passphrase, shares can be converted.
    """
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]

    # Rework to extendable with a new group configuration.
    reworked = shamir.rework_mnemonics(
        original[:3], b"TREZOR", extendable=True, group_threshold=1, groups=[(2, 3)]
    )

    # The reworked shares recover the same master secret.
    assert MS == shamir.combine_mnemonics(reworked[0][:2], b"TREZOR")

    # Verify that the new shares are actually marked extendable:
    # Two independently reworked sets should give consistent wrong-passphrase results,
    # since extendable shares use empty salt.
    reworked2 = shamir.rework_mnemonics(
        original[:3], b"TREZOR", extendable=True, group_threshold=1, groups=[(2, 3)]
    )
    wrong_pw1 = shamir.combine_mnemonics(reworked[0][:2])
    wrong_pw2 = shamir.combine_mnemonics(reworked2[0][:2])
    assert wrong_pw1 == wrong_pw2  # Extendable: consistent for any passphrase


def test_rework_extendable_to_non_extendable():
    """Extendable shares can be reworked to non-extendable given the passphrase."""
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=True)[0]

    reworked = shamir.rework_mnemonics(
        original[:3], b"TREZOR", extendable=False, group_threshold=1, groups=[(2, 3)]
    )

    # The reworked shares recover the same master secret.
    assert MS == shamir.combine_mnemonics(reworked[0][:2], b"TREZOR")


def test_rework_preserves_iteration_exponent():
    """rework_mnemonics preserves the original iteration exponent by default."""
    original = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=False, iteration_exponent=2
    )[0]

    reworked = shamir.rework_mnemonics(
        original[:3], b"TREZOR", extendable=True, group_threshold=1, groups=[(2, 3)]
    )

    # Recover and verify: the iteration exponent is preserved.
    assert MS == shamir.combine_mnemonics(reworked[0][:2], b"TREZOR")

    # Verify the iteration exponent is preserved by checking the EMS.
    groups = shamir.decode_mnemonics(reworked[0][:2])
    ems = shamir.recover_ems(groups)
    assert ems.iteration_exponent == 2


def test_rework_with_wrong_passphrase():
    """Reworking with a wrong passphrase produces shares that don't recover the
    original secret (but don't raise an error either — the Feistel cipher has no
    authentication).
    """
    original = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]

    # Rework with wrong passphrase.
    reworked = shamir.rework_mnemonics(
        original[:3], b"WRONG", extendable=True, group_threshold=1, groups=[(2, 3)]
    )

    # The reworked shares do NOT recover the original master secret with any passphrase.
    assert MS != shamir.combine_mnemonics(reworked[0][:2], b"TREZOR")
    assert MS != shamir.combine_mnemonics(reworked[0][:2], b"WRONG")
    assert MS != shamir.combine_mnemonics(reworked[0][:2])


def test_verify_correct_shares():
    """verify_mnemonics returns True for correctly generated shares."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]
    assert shamir.verify_mnemonics(mnemonics[:3], b"TREZOR", MS) is True


def test_verify_correct_extendable_shares():
    """verify_mnemonics returns True for correctly generated extendable shares."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=True)[
        0
    ]
    assert shamir.verify_mnemonics(mnemonics[:3], b"TREZOR", MS) is True


def test_verify_wrong_passphrase():
    """verify_mnemonics returns False when the passphrase is wrong."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR", extendable=False)[
        0
    ]
    assert shamir.verify_mnemonics(mnemonics[:3], b"WRONG", MS) is False


def test_verify_detects_wrong_salt_mode():
    """verify_mnemonics can detect shares encrypted with the wrong salt mode.

    This simulates a buggy implementation that marks shares as non-extendable but
    uses empty salt (the extendable mode) for encryption.
    """
    identifier = 12345
    iteration_exponent = 1

    # Encrypt with EXTENDABLE (empty) salt...
    ems_buggy = shamir.EncryptedMasterSecret.from_master_secret(
        MS,
        b"TREZOR",
        identifier,
        extendable=True,
        iteration_exponent=iteration_exponent,
    )

    # ...but create shares marked as NON-EXTENDABLE (wrong flag).
    buggy_shares = shamir.split_ems(
        1,
        [(3, 5)],
        shamir.EncryptedMasterSecret(
            identifier, False, iteration_exponent, ems_buggy.ciphertext
        ),
    )
    buggy_mnemonics = [share.mnemonic() for share in buggy_shares[0]]

    # verify_mnemonics detects the mismatch: the shares say non-extendable,
    # but the ciphertext was encrypted with extendable (empty) salt.
    assert shamir.verify_mnemonics(buggy_mnemonics[:3], b"TREZOR", MS) is False

    # However, if we decrypt treating the shares as extendable (ignoring the flag),
    # we get the correct master secret.
    groups = shamir.decode_mnemonics(buggy_mnemonics[:3])
    ems = shamir.recover_ems(groups)

    # Decrypt with extendable=True (the actual salt mode used).
    ems_fixed = shamir.EncryptedMasterSecret(
        ems.identifier, True, ems.iteration_exponent, ems.ciphertext
    )
    assert ems_fixed.decrypt(b"TREZOR") == MS

    # Decrypt with extendable=False (what the flag says) gives wrong result.
    assert ems.decrypt(b"TREZOR") != MS
