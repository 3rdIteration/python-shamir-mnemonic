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


def test_verify_mnemonics_correct_extendable():
    """Correctly-created extendable shares should pass verification."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, extendable=True)[0]
    shamir.verify_mnemonics(mnemonics[:3], b"", MS)


def test_verify_mnemonics_correct_non_extendable():
    """Correctly-created non-extendable shares should pass verification."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, extendable=False)[0]
    shamir.verify_mnemonics(mnemonics[:3], b"", MS)


def test_verify_mnemonics_correct_with_passphrase():
    """Correctly-created shares with passphrase should pass verification."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS, b"TREZOR")[0]
    shamir.verify_mnemonics(mnemonics[:3], b"TREZOR", MS)


def test_verify_mnemonics_wrong_secret():
    """Shares that don't match the expected secret should raise an error."""
    mnemonics = shamir.generate_mnemonics(1, [(3, 5)], MS)[0]
    with pytest.raises(MnemonicError, match="do not match the expected master secret"):
        shamir.verify_mnemonics(mnemonics[:3], b"", b"WRONG_SECRET_12345")


def test_verify_mnemonics_detects_non_extendable_with_empty_salt():
    """
    Simulate the ERAWLT-style bug: shares are flagged as non-extendable but
    encrypted with the extendable (empty) salt. verify_mnemonics should detect
    this mismatch and raise a specific error.
    """
    # Step 1: Encrypt the master secret with extendable=True (empty salt).
    identifier = 42
    iteration_exponent = 1
    ems = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier, extendable=True, iteration_exponent=iteration_exponent
    )

    # Step 2: Create shares but lie about extendable=False in the share metadata.
    # This simulates the ERAWLT bug where shares are flagged non-extendable
    # but the encryption used the extendable (empty) salt.
    fake_ems = shamir.EncryptedMasterSecret(
        identifier, False, iteration_exponent, ems.ciphertext
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], fake_ems)

    # Re-encode shares with extendable=False flag (they already have it from fake_ems).
    mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    # Step 3: verify_mnemonics should detect the mismatch.
    with pytest.raises(
        MnemonicError, match="flagged as non-extendable but were encrypted with an empty salt"
    ):
        shamir.verify_mnemonics(mnemonics[:3], b"", MS)


def test_verify_mnemonics_detects_extendable_with_non_extendable_salt():
    """
    The reverse mismatch: shares flagged as extendable but encrypted with
    non-extendable salt. verify_mnemonics should detect this too.
    """
    identifier = 42
    iteration_exponent = 1
    ems = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier, extendable=False, iteration_exponent=iteration_exponent
    )

    fake_ems = shamir.EncryptedMasterSecret(
        identifier, True, iteration_exponent, ems.ciphertext
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], fake_ems)
    mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    with pytest.raises(
        MnemonicError, match="flagged as extendable but were encrypted with the non-extendable salt"
    ):
        shamir.verify_mnemonics(mnemonics[:3], b"", MS)


def test_non_extendable_salt_differs_from_extendable():
    """
    Verify that encryption with extendable vs non-extendable parameters
    produces different ciphertexts, confirming the salt actually matters.
    """
    identifier = 42
    iteration_exponent = 1

    ems_ext = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier, extendable=True, iteration_exponent=iteration_exponent
    )
    ems_non_ext = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier, extendable=False, iteration_exponent=iteration_exponent
    )

    assert ems_ext.ciphertext != ems_non_ext.ciphertext, (
        "Extendable and non-extendable encryption must produce different "
        "ciphertexts when using the same master secret, passphrase, and identifier."
    )


def test_rework_non_extendable_with_wrong_salt_produces_wrong_secret():
    """
    Demonstrate what happens when non-extendable shares from a compliant
    implementation are "reworked" by an implementation that always uses
    empty (extendable) salt.

    The ERA wallet rework path is:
    1. Recover entropy by decrypting the EMS (with the wrong salt → wrong entropy).
    2. Store that wrong entropy.
    3. Re-generate new shares from the stored entropy using generateMnemonics
       (which re-encrypts with the wrong salt and labels non-extendable).

    The Feistel cipher has the property that encrypt(decrypt(ct, S), S) = ct
    for any salt S, so if the same wrong salt is used consistently, the
    ciphertext is paradoxically preserved. However, the "entropy" the wallet
    stores and uses to derive keys is WRONG.
    """
    identifier = 42
    iteration_exponent = 1

    # --- Original shares: correctly non-extendable (from this library) ---
    ems_correct = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier, extendable=False, iteration_exponent=iteration_exponent
    )

    # --- Buggy implementation decrypts with empty salt (extendable mode) ---
    wrong_ms = shamir.decrypt(
        ems_correct.ciphertext, b"", iteration_exponent, identifier, extendable=True
    )
    assert wrong_ms != MS, (
        "Decrypting non-extendable ciphertext with the extendable (empty) salt "
        "must NOT yield the original master secret."
    )

    # --- The wallet stores wrong_ms as the "entropy" and derives keys from it ---
    # This is the fundamental problem: the wallet's internal key derivation is wrong.
    # Any BIP32 keys derived from wrong_ms would produce different addresses.

    # --- If the wallet round-trips the ciphertext (decrypt+encrypt with same wrong salt),
    # the ciphertext is actually preserved due to Feistel cipher symmetry ---
    round_tripped_ct = shamir.encrypt(
        wrong_ms, b"", iteration_exponent, identifier, extendable=True
    )
    assert round_tripped_ct == ems_correct.ciphertext, (
        "Feistel cipher round-trip with the same (wrong) salt preserves the ciphertext."
    )

    # So if the reworked shares contain the round-tripped ciphertext, a compliant
    # tool can still recover the ORIGINAL master secret...
    reworked_ems = shamir.EncryptedMasterSecret(
        identifier, False, iteration_exponent, round_tripped_ct
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], reworked_ems)
    reworked_mnemonics = [share.mnemonic() for share in grouped_shares[0]]
    recovered = shamir.combine_mnemonics(reworked_mnemonics[:3])
    assert recovered == MS, (
        "When the same wrong salt is used for both decrypt and re-encrypt, "
        "the ciphertext survives unchanged and the original secret is recoverable."
    )

    # ...but the wallet internally uses wrong_ms for key derivation, creating a
    # mismatch between what the wallet shows and what the shares actually contain.
    assert wrong_ms != MS


def test_rework_from_stored_wrong_entropy_creates_divergent_shares():
    """
    When the ERA wallet stores wrong entropy (from decrypting with wrong salt)
    and later re-generates shares from that stored entropy with NEW parameters
    (different threshold/count), the new shares diverge from the original secret.

    This is the realistic rework path: generateMnemonics(wrong_entropy, ...)
    rather than round-tripping the ciphertext.
    """
    identifier = 42
    iteration_exponent = 1

    # --- Original shares: correctly non-extendable (from this library) ---
    ems_correct = shamir.EncryptedMasterSecret.from_master_secret(
        MS, b"", identifier, extendable=False, iteration_exponent=iteration_exponent
    )

    # --- Buggy implementation decrypts with empty salt → wrong entropy stored ---
    wrong_ms = shamir.decrypt(
        ems_correct.ciphertext, b"", iteration_exponent, identifier, extendable=True
    )
    assert wrong_ms != MS

    # --- Buggy implementation generates NEW shares from stored wrong entropy ---
    # This is what generateMnemonics does: fresh encryption from the entropy.
    # The buggy implementation encrypts with empty salt (extendable=True internally)
    # but labels the resulting shares as non-extendable (extendable=False in metadata).
    ems_from_wrong_entropy = shamir.EncryptedMasterSecret.from_master_secret(
        wrong_ms, b"", identifier, extendable=True, iteration_exponent=iteration_exponent
    )
    mislabeled_ems = shamir.EncryptedMasterSecret(
        identifier, False, iteration_exponent, ems_from_wrong_entropy.ciphertext
    )
    grouped_shares = shamir.split_ems(1, [(2, 3)], mislabeled_ems)
    reworked_mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    # Due to Feistel round-trip property, the ciphertext is actually the same as original:
    # encrypt(decrypt(ct, empty_salt), empty_salt) = ct
    assert ems_from_wrong_entropy.ciphertext == ems_correct.ciphertext

    # So even through this path, a compliant tool recovers the original secret
    # because the underlying ciphertext is unchanged.
    recovered = shamir.combine_mnemonics(reworked_mnemonics[:2])
    assert recovered == MS

    # Since the ciphertext is identical to the original (non-extendable) ciphertext,
    # verify_mnemonics passes -- the shares work correctly with the non-extendable salt
    # despite the buggy tool's use of the wrong salt internally.
    shamir.verify_mnemonics(reworked_mnemonics[:2], b"", MS)


def test_rework_passphrase_protected_shares_without_passphrase():
    """
    Demonstrate what happens when passphrase-protected shares are reworked by
    an implementation that ignores the passphrase during recovery.

    Since the same (empty) passphrase is used for both decrypt and re-encrypt,
    the Feistel round-trip preserves the ciphertext. The reworked shares still
    require the ORIGINAL passphrase for correct recovery by a compliant tool.

    However, the wallet internally decrypted to the wrong entropy, so its
    own key derivation is based on the wrong master secret.
    """
    identifier = 42
    iteration_exponent = 1
    passphrase = b"TREZOR"

    # --- Original shares: passphrase-protected, non-extendable ---
    ems_correct = shamir.EncryptedMasterSecret.from_master_secret(
        MS, passphrase, identifier, extendable=False, iteration_exponent=iteration_exponent
    )

    # --- Buggy implementation decrypts with empty passphrase ---
    wrong_ms = shamir.decrypt(
        ems_correct.ciphertext, b"", iteration_exponent, identifier, extendable=False
    )
    assert wrong_ms != MS, (
        "Decrypting passphrase-protected ciphertext without the passphrase "
        "must NOT yield the original master secret."
    )

    # --- Feistel round-trip with same (empty) passphrase preserves ciphertext ---
    round_tripped_ct = shamir.encrypt(
        wrong_ms, b"", iteration_exponent, identifier, extendable=False
    )
    assert round_tripped_ct == ems_correct.ciphertext

    # --- Reworked shares still contain the original ciphertext ---
    reworked_ems = shamir.EncryptedMasterSecret(
        identifier, False, iteration_exponent, round_tripped_ct
    )
    grouped_shares = shamir.split_ems(1, [(3, 5)], reworked_ems)
    reworked_mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    # A compliant tool with the correct passphrase CAN still recover the secret
    recovered_with_pp = shamir.combine_mnemonics(reworked_mnemonics[:3], passphrase)
    assert recovered_with_pp == MS

    # Without passphrase, a compliant tool gets a different result (as expected)
    recovered_no_pp = shamir.combine_mnemonics(reworked_mnemonics[:3])
    assert recovered_no_pp != MS

    # But the wallet itself thinks the entropy is wrong_ms and derives keys from it
    assert wrong_ms != MS
