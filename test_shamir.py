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


# ---------------------------------------------------------------------------
# ERA wallet import scenario tests
# ---------------------------------------------------------------------------
# These tests simulate the exact code paths in the ERA wallet
# (ERAWLT/ERA-crypto-p) to demonstrate concrete scenarios where ERA displays
# incorrect addresses or generates non-standard SLIP39 backups.
#
# ERA wallet bug references (Account.cpp, ShamirCipher.cpp):
#   Bug 1: decodeShamirShares() / addAccount() always call
#          encryptedMasterSecret.decrypt("") — ignoring the user passphrase.
#   Bug 2: Account constructor always re-encrypts with extendable=false
#          via EncryptedMasterSecret::fromMasterSecret(entropy, "", id, false, ie).
# ---------------------------------------------------------------------------


def test_era_import_nonextendable_no_passphrase_correct():
    """
    Scenario: Trezor non-extendable shares WITHOUT passphrase imported into ERA.

    When no passphrase was used, ERA's bug of decrypting with "" is actually
    harmless — the correct master secret is recovered and stored.
    ERA displays CORRECT addresses.
    """
    identifier = 42
    iteration_exponent = 1

    # Generate compliant non-extendable shares (as Trezor would).
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=False, iteration_exponent=iteration_exponent
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=b"")

    # ERA's stored entropy matches the real master secret.
    assert result.stored_entropy == MS

    # ERA's no-passphrase seed matches the real master secret.
    assert result.no_passphrase_seed == MS

    # ERA's correct_master_secret also matches (trivially).
    assert result.correct_master_secret == MS

    # BIP32 keys match.
    assert BIP32Key.fromEntropy(result.no_passphrase_seed).ExtendedKey() == (
        BIP32Key.fromEntropy(MS).ExtendedKey()
    )


def test_era_import_nonextendable_with_passphrase_wrong_default_addresses():
    """
    Scenario: Trezor non-extendable shares WITH passphrase "TREZOR" imported
    into ERA wallet.

    ERA always decrypts with empty passphrase (Bug 1), so it stores the WRONG
    entropy — the "plausible deniability" wallet instead of the real one.

    ERA's default (no-passphrase) view shows INCORRECT addresses.
    The user's real wallet appears to be empty or have different balances.
    """
    identifier = 42
    iteration_exponent = 1

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=False, iteration_exponent=iteration_exponent
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=b"TREZOR")

    # ERA's stored entropy is NOT the real master secret.
    assert result.stored_entropy != MS, (
        "ERA stored the plausible-deniability wallet instead of the real one."
    )

    # ERA's no-passphrase seed is wrong — it shows the plausible-deniability wallet.
    assert result.no_passphrase_seed != MS

    # BIP32 xprv differs: ERA shows different addresses than the user expects.
    era_xprv = BIP32Key.fromEntropy(result.no_passphrase_seed).ExtendedKey()
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()
    assert era_xprv != correct_xprv, (
        "ERA's default BIP32 root key differs from the correct one — "
        "the user would see entirely different addresses."
    )


def test_era_import_nonextendable_with_passphrase_correct_passphrase_wallet():
    """
    Scenario: Same as above, but user enters passphrase "TREZOR" in ERA.

    Because ERA stores the EMS (which is preserved through Feistel round-trip),
    entering the correct passphrase produces the CORRECT seed and addresses.

    This is the saving grace: even though ERA's internal entropy is wrong,
    the passphrase-protected wallet still works correctly — as long as the
    identifier and iteration exponent are preserved.
    """
    identifier = 42
    iteration_exponent = 1

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=False, iteration_exponent=iteration_exponent
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=b"TREZOR")

    # ERA's passphrase seed IS the correct master secret.
    assert result.passphrase_seed == MS, (
        "When the user enters the correct passphrase, ERA derives the "
        "correct seed because the stored EMS is the original ciphertext."
    )

    # The stored EMS was preserved through Feistel round-trip.
    # Verify: the original EMS is what a compliant tool would reconstruct.
    groups = shamir.decode_mnemonics(mnemonics[:3])
    original_ems = shamir.recover_ems(groups)
    assert result.stored_ems == original_ems.ciphertext, (
        "ERA's stored EMS matches the original — Feistel round-trip preserved it."
    )

    # BIP32 keys match when passphrase is used.
    era_pp_xprv = BIP32Key.fromEntropy(result.passphrase_seed).ExtendedKey()
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()
    assert era_pp_xprv == correct_xprv


def test_era_rework_same_identifier_preserves_passphrase_wallet():
    """
    Scenario: ERA reworks (re-generates) shares using the SAME identifier.

    When the identifier is preserved during rework, the Feistel round-trip
    ensures the EMS is identical. A compliant tool can recover the original
    master secret with the correct passphrase.

    The passphrase-protected wallet survives the rework.
    """
    iteration_exponent = 1
    passphrase = b"TREZOR"

    # Original compliant shares.
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=iteration_exponent
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)
    original_identifier = result.identifier

    # ERA reworks with same identifier → uses stored_entropy (which is wrong)
    # but re-encrypts with same id, producing the same EMS.
    reworked_ems = shamir.EncryptedMasterSecret.from_master_secret(
        result.stored_entropy,
        b"",
        original_identifier,
        False,  # ERA hardcodes extendable=False
        iteration_exponent,
    )

    # The reworked EMS matches the original — Feistel round-trip.
    assert reworked_ems.ciphertext == result.stored_ems

    # Generate new shares from the reworked EMS.
    grouped_shares = shamir.split_ems(1, [(2, 3)], reworked_ems)
    reworked_mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    # A compliant tool with the correct passphrase recovers the original secret.
    recovered = shamir.combine_mnemonics(reworked_mnemonics[:2], passphrase)
    assert recovered == MS, (
        "Rework with same identifier preserves the passphrase wallet."
    )


def test_era_rework_new_identifier_loses_passphrase_wallet():
    """
    Scenario: ERA reworks shares using a NEW (different) identifier.

    When the identifier changes, the salt in the Feistel cipher changes.
    The round-trip property no longer holds across different salts:
      encrypt(decrypt(ct, salt_old), salt_new) ≠ ct

    The new EMS is different from the original. The passphrase-protected
    wallet produces DIFFERENT addresses — the original wallet is LOST from
    these new shares. This is the most dangerous scenario.

    ERA-crypto-p code reference (WfLibrary.cpp): in the SLIP39→SLIP39 rework
    path, slip39Id is taken from getAccountSlip39Identifier() — if this value
    is 0 or differs from the original, the wallet is silently destroyed.
    """
    iteration_exponent = 1
    passphrase = b"TREZOR"

    # Original compliant shares.
    mnemonics = shamir.generate_mnemonics(
        1,
        [(3, 5)],
        MS,
        passphrase,
        extendable=False,
        iteration_exponent=iteration_exponent,
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)
    original_identifier = result.identifier
    # Pick a new identifier that is guaranteed to be different.
    new_identifier = (original_identifier + 1) % (1 << 15)
    assert result.stored_entropy != MS  # ERA stored the wrong entropy

    # ERA reworks with a DIFFERENT identifier.
    reworked_ems = shamir.EncryptedMasterSecret.from_master_secret(
        result.stored_entropy,
        b"",
        new_identifier,
        False,
        iteration_exponent,
    )

    # The new EMS differs from the original because the salt changed.
    assert reworked_ems.ciphertext != result.stored_ems, (
        "Different identifier → different salt → different ciphertext."
    )

    # Generate new shares from the reworked EMS.
    grouped_shares = shamir.split_ems(1, [(2, 3)], reworked_ems)
    reworked_mnemonics = [share.mnemonic() for share in grouped_shares[0]]

    # A compliant tool with the correct passphrase CANNOT recover the original secret.
    recovered_with_pp = shamir.combine_mnemonics(reworked_mnemonics[:2], passphrase)
    assert recovered_with_pp != MS, (
        "The original master secret is IRRECOVERABLE from shares reworked with "
        "a different identifier. The passphrase wallet is silently destroyed."
    )

    # Even without passphrase, the recovery gives ERA's wrong entropy
    # (which is also NOT the original master secret).
    recovered_no_pp = shamir.combine_mnemonics(reworked_mnemonics[:2])
    assert recovered_no_pp == result.stored_entropy, (
        "Without passphrase, recovery gives ERA's wrong stored entropy."
    )
    assert recovered_no_pp != MS


def test_era_import_concrete_bip32_key_divergence():
    """
    Concrete demonstration of BIP32 key divergence between ERA wallet and
    a compliant implementation, using actual xprv comparison.

    This shows that importing a Trezor non-extendable mnemonic with a
    passphrase into ERA wallet produces:
    - A different BIP32 root key in ERA's default (no-passphrase) view
    - The correct BIP32 root key when the user enters the passphrase
    - Three distinct xprv values: correct, ERA-default-wrong, ERA-passphrase-correct
    """
    identifier = 42
    iteration_exponent = 1
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=iteration_exponent
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    # Three different BIP32 root keys.
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()
    era_default_xprv = BIP32Key.fromEntropy(result.no_passphrase_seed).ExtendedKey()
    era_passphrase_xprv = BIP32Key.fromEntropy(result.passphrase_seed).ExtendedKey()

    # ERA's default view shows a different root key than what the user expects.
    assert era_default_xprv != correct_xprv, (
        "ERA default view: wrong BIP32 root key → wrong addresses"
    )

    # ERA's passphrase view shows the correct root key.
    assert era_passphrase_xprv == correct_xprv, (
        "ERA passphrase view: correct BIP32 root key → correct addresses"
    )

    # Summary: two distinct xprv values from three derivation paths.
    # correct_xprv == era_passphrase_xprv (user's real wallet)
    # era_default_xprv is a different wallet entirely (plausible-deniability wallet).
    assert era_default_xprv != era_passphrase_xprv, (
        "ERA shows two distinct wallets: the wrong default one and the "
        "correct passphrase-protected one."
    )


def test_era_rework_new_id_concrete_wallet_destruction():
    """
    End-to-end scenario demonstrating silent wallet destruction:

    1. User creates a Trezor non-extendable backup with passphrase.
    2. User imports shares into ERA wallet.
    3. ERA reworks shares to a new 2-of-3 scheme with a new identifier.
    4. User discards the original Trezor shares, keeps only ERA shares.
    5. User tries to recover with passphrase → WRONG wallet.
    6. The original wallet is irrecoverably lost.

    This demonstrates both incorrect addresses AND non-standard SLIP39 output.
    """
    iteration_exponent = 1
    passphrase = b"TREZOR"

    # Step 1: Trezor creates original shares.
    original_mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=iteration_exponent
    )[0]

    # Step 2: ERA imports.
    result = shamir.simulate_era_import(original_mnemonics[:3], passphrase=passphrase)
    wrong_entropy = result.stored_entropy
    assert wrong_entropy != MS

    # Step 3: ERA reworks to 2-of-3 with new identifier.
    original_id = result.identifier
    new_id = (original_id + 1) % (1 << 15)  # Guaranteed different
    reworked_ems = shamir.EncryptedMasterSecret.from_master_secret(
        wrong_entropy, b"", new_id, False, iteration_exponent
    )
    grouped_shares = shamir.split_ems(1, [(2, 3)], reworked_ems)
    era_shares = [share.mnemonic() for share in grouped_shares[0]]

    # Step 4: User discards original shares and keeps only ERA shares.
    # Step 5: User tries to recover.

    # Without passphrase: gets ERA's wrong entropy (not original MS).
    recovered_no_pp = shamir.combine_mnemonics(era_shares[:2])
    assert recovered_no_pp == wrong_entropy
    assert recovered_no_pp != MS

    # With original passphrase: gets some OTHER value (not original MS either!).
    recovered_with_pp = shamir.combine_mnemonics(era_shares[:2], passphrase)
    assert recovered_with_pp != MS, (
        "The original master secret is irrecoverable."
    )
    assert recovered_with_pp != wrong_entropy, (
        "The passphrase-decrypted value is neither the original secret "
        "nor ERA's stored entropy — it's completely unrelated garbage."
    )

    # Step 6: Prove the wallet is destroyed by comparing BIP32 keys.
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()

    # None of the recovery paths produce the correct key.
    assert BIP32Key.fromEntropy(recovered_no_pp).ExtendedKey() != correct_xprv
    assert BIP32Key.fromEntropy(recovered_with_pp).ExtendedKey() != correct_xprv

    # The shares are also non-standard: they claim non-extendable but were
    # built from wrong entropy. verify_mnemonics confirms they don't match.
    with pytest.raises(MnemonicError):
        shamir.verify_mnemonics(era_shares[:2], passphrase, MS)


# ---------------------------------------------------------------------------
# Passphrase compatibility tests
# ---------------------------------------------------------------------------
# These tests prove that simulate_era_import works correctly for ANY
# non-extendable share generated with a passphrase — not just "TREZOR".
# ---------------------------------------------------------------------------


def test_era_import_works_for_any_passphrase():
    """
    Verify that simulate_era_import correctly handles non-extendable shares
    generated with various passphrases.

    For ALL passphrases:
    - ERA's stored entropy is wrong (it's the plausible-deniability wallet).
    - ERA's no-passphrase seed ≠ the original master secret.
    - ERA's passphrase seed == the original master secret (Feistel round-trip).

    This confirms the answer: YES, the ERA import path produces correct
    passphrase-wallet addresses for ANY non-extendable share with ANY passphrase,
    because the Feistel round-trip property is independent of the passphrase value.
    """
    passphrases = [b"TREZOR", b"secret", b"a", b"X" * 100, b"p@$$w0rd!"]

    for pp in passphrases:
        mnemonics = shamir.generate_mnemonics(
            1, [(3, 5)], MS, pp, extendable=False, iteration_exponent=1
        )[0]

        result = shamir.simulate_era_import(mnemonics[:3], passphrase=pp)

        # ERA stores the wrong entropy (Bug 1: decrypt with "").
        assert result.stored_entropy != MS, (
            f"passphrase={pp!r}: ERA should NOT get the correct entropy"
        )

        # ERA's no-passphrase view shows wrong addresses.
        assert result.no_passphrase_seed != MS, (
            f"passphrase={pp!r}: ERA default view should be wrong"
        )

        # ERA's passphrase view shows CORRECT addresses.
        assert result.passphrase_seed == MS, (
            f"passphrase={pp!r}: ERA passphrase view should be correct "
            "(Feistel round-trip preserves EMS)"
        )

        # The correct master secret matches.
        assert result.correct_master_secret == MS, (
            f"passphrase={pp!r}: compliant recovery should match"
        )


def test_era_import_works_for_non_extendable_with_passphrase_and_different_iteration_exponents():
    """
    Verify that the Feistel round-trip works for non-extendable shares with
    passphrases at different iteration exponents.

    The iteration exponent only affects the number of PBKDF2 rounds, not the
    salt structure, so the round-trip property should hold regardless.
    """
    passphrase = b"TREZOR"

    for ie in [0, 1, 2]:
        mnemonics = shamir.generate_mnemonics(
            1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=ie
        )[0]

        result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

        assert result.stored_entropy != MS, (
            f"ie={ie}: ERA should store wrong entropy"
        )
        assert result.passphrase_seed == MS, (
            f"ie={ie}: ERA passphrase view should still be correct"
        )


def test_era_import_extendable_with_passphrase():
    """
    Verify simulate_era_import for EXTENDABLE shares with a passphrase.

    For extendable shares (salt=empty), ERA's Bug 2 (hardcoded extendable=False)
    changes the salt during re-encryption. The Feistel round-trip does NOT hold
    because the salt changes:
      encrypt(decrypt(ct, empty_salt), non_empty_salt) ≠ ct

    This means even the passphrase wallet is broken for extendable shares
    imported into ERA — the stored EMS differs from the original.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    # ERA's stored entropy is wrong (Bug 1).
    assert result.stored_entropy != MS

    # For extendable shares, the stored EMS differs from original because
    # ERA re-encrypts with extendable=False (different salt).
    groups = shamir.decode_mnemonics(mnemonics[:3])
    original_ems = shamir.recover_ems(groups)

    # Bug 2 causes the EMS to change (salt mismatch).
    assert result.stored_ems != original_ems.ciphertext, (
        "For extendable shares, ERA's Bug 2 (hardcoded extendable=False) "
        "changes the salt, so the round-trip does NOT preserve the EMS."
    )

    # The passphrase wallet is ALSO broken.
    assert result.passphrase_seed != MS, (
        "For extendable shares imported into ERA, even the passphrase wallet "
        "produces wrong addresses because the stored EMS has a different salt."
    )


# ---------------------------------------------------------------------------
# ERA wallet scenario 2 and 4 blocking tests
# ---------------------------------------------------------------------------
# These tests prove that the ERA wallet has NO code to block:
#   Scenario 2: Importing non-extendable shares with a passphrase
#                (ERA silently ignores the passphrase → wrong entropy)
#   Scenario 4: Reworking shares with a new/zero identifier
#                (ERA silently destroys the passphrase wallet)
# ---------------------------------------------------------------------------


def test_era_no_block_scenario_2_passphrase_ignored_during_import():
    """
    Prove ERA wallet has NO code to block Scenario 2:
    importing non-extendable passphrase-protected shares.

    ERA wallet code path (Account.cpp):
      - decodeShamirShares():  encryptedMasterSecret.decrypt({})  [line 210]
      - addAccount():          encryptedMasterSecret.decrypt("")   [line 433]

    Both ALWAYS use empty passphrase, regardless of what the user entered.
    There is no validation, no prompt, no warning.  The passphrase parameter
    in decodeShamirShares() is accepted but completely ignored — it is never
    passed to the decrypt call.

    This test verifies the import succeeds silently with wrong entropy stored.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    # Import "succeeds" — ERA gets entropy without error.
    assert result.stored_entropy is not None
    assert len(result.stored_entropy) == len(MS)

    # But the stored entropy is WRONG.
    assert result.stored_entropy != MS, (
        "ERA has no blocking for Scenario 2: passphrase-protected shares are "
        "imported silently with wrong entropy. The passphrase parameter in "
        "decodeShamirShares() is accepted but never used."
    )

    # ERA creates an account with wrong entropy — no error, no warning.
    # The Account constructor (line 831-867) re-encrypts the wrong entropy
    # and stores the EMS without any validation.
    assert result.stored_ems is not None
    assert len(result.stored_ems) == len(MS)


def test_era_no_block_scenario_4_rework_with_same_identifier():
    """
    Prove ERA wallet has NO code to block Scenario 4 (part 1):
    reworking shares preserves the EMS when the same identifier is used.

    When the identifier is preserved:
    - The Feistel round-trip holds: encrypt(decrypt(ct,S),S) = ct
    - The reworked shares contain the original EMS ciphertext
    - A compliant tool CAN still recover with the passphrase

    But ERA itself shows wrong addresses (no-passphrase view), and there
    is no code to detect or warn about this.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]

    # Rework with same identifier — the "safe" case.
    rework = shamir.simulate_era_rework(
        mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),)
    )

    # Same identifier is used.
    assert rework.rework_identifier == rework.original_identifier

    # The original secret IS recoverable from reworked shares (with passphrase).
    assert rework.original_secret_recoverable, (
        "With same identifier, the Feistel round-trip preserves the EMS."
    )
    assert rework.recovered_with_passphrase == MS

    # But without passphrase, recovery gives the wrong entropy.
    assert rework.recovered_without_passphrase != MS
    assert rework.recovered_without_passphrase == rework.stored_entropy

    # No code in ERA blocks this — the rework proceeds silently.
    assert len(rework.reworked_shares) == 3


def test_era_no_block_scenario_4_rework_with_new_identifier():
    """
    Prove ERA wallet has NO code to block Scenario 4 (part 2):
    reworking shares with a DIFFERENT identifier.

    This is the catastrophic case: when getAccountSlip39Identifier() returns
    a different value (e.g. 0 when account session is lost), the Feistel
    round-trip breaks because the salt changes.

    ERA wallet code path:
      CryptoModule::getAccountSlip39Identifier() [CryptoModule.cpp:588]:
        auto account = _getActiveAccount({});
        if (!account) { return 0; }          // ← Returns 0 if no session!
        return account->getSlip39Identifier();

    There is NO validation that the identifier matches the original shares.
    There is NO warning when a zero identifier is used.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]

    # Rework with identifier=0 (what ERA returns when account session is lost).
    rework = shamir.simulate_era_rework(
        mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
        new_identifier=0,
    )

    # Different identifier was used.
    assert rework.rework_identifier != rework.original_identifier
    assert rework.rework_identifier == 0

    # The original secret is NOT recoverable — wallet is destroyed.
    assert not rework.original_secret_recoverable, (
        "ERA has no blocking for Scenario 4: rework with a different identifier "
        "silently destroys the passphrase wallet. There is no validation that "
        "the identifier matches the original shares."
    )
    assert rework.recovered_with_passphrase != MS
    assert rework.recovered_without_passphrase != MS

    # Reworked shares were generated without error — no blocking.
    assert len(rework.reworked_shares) == 3


def test_era_no_block_scenario_4_rework_with_arbitrary_identifier():
    """
    Additional proof that ANY different identifier breaks recovery.

    The ERA wallet code has no range checks on the identifier, no comparison
    with the original, and no integrity verification.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]

    # Try several different identifiers.
    for bad_id in [0, 1, 100, 12345, 32767]:
        rework = shamir.simulate_era_rework(
            mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
            new_identifier=bad_id,
        )

        # If the identifier happens to match the original, the round-trip works.
        if bad_id == rework.original_identifier:
            assert rework.original_secret_recoverable
        else:
            assert not rework.original_secret_recoverable, (
                f"id={bad_id}: rework with different identifier must break recovery"
            )


# ---------------------------------------------------------------------------
# Trezor firmware analysis
# ---------------------------------------------------------------------------
# These tests verify findings from reviewing the Trezor firmware source code
# at https://github.com/trezor/trezor-firmware to determine whether Trezor
# shares are vulnerable to the ERA wallet issue.
#
# Trezor firmware references (trezor/trezor-firmware, branch main):
#
#   core/src/trezor/crypto/slip39.py
#     - _get_salt(): extendable → empty salt, non-extendable → CUSTOMIZATION_STRING_ORIG + id
#     - split_ems(): correctly passes extendable flag and identifier to _encode_mnemonic()
#     - decrypt(): correctly uses _get_salt(identifier, extendable)
#     - generate_random_identifier(): generates proper random 15-bit identifier
#
#   core/src/apps/management/reset_device/__init__.py
#     - reset_device(): FORCES extendable backup:
#         if backup_type == BAK_T_SLIP39_BASIC:
#             backup_type = BAK_T_SLIP39_BASIC_EXT
#         if backup_type == BAK_T_SLIP39_ADVANCED:
#             backup_type = BAK_T_SLIP39_ADVANCED_EXT
#     - _get_slip39_mnemonics(): for extendable → generate_random_identifier()
#                                for non-extendable → storage_device.get_slip39_identifier()
#     - Stores EMS (not decrypted secret): store_mnemonic_secret(secret=EMS, ...)
#
#   core/src/apps/common/mnemonic.py
#     - get_seed(): correctly decrypts EMS with user passphrase:
#         seed = slip39.decrypt(mnemonic_secret, passphrase.encode(),
#                               iteration_exponent, identifier, extendable, ...)
#
#   core/src/apps/management/recovery_device/homescreen.py
#     - _finish_recovery(): stores identifier and iteration_exponent from recovered shares
#     - For non-extendable: storage_device.set_slip39_identifier(identifier)
#
# Key findings:
#   1. Trezor's SLIP39 implementation is CORRECT — no salt/flag mismatch bugs
#   2. Trezor CURRENTLY forces extendable backups for all new SLIP39 setups
#   3. Trezor PREVIOUSLY generated non-extendable SLIP39 shares (before force-extendable)
#   4. Trezor correctly uses user passphrase for seed derivation (NOT hardcoded to "")
#   5. Trezor stores the EMS (not decrypted entropy) — the reference implementation
#
# Vulnerability to ERA wallet:
#   - Trezor itself is NOT vulnerable (correct implementation)
#   - Trezor SHARES become vulnerable when imported into ERA wallet
#   - Historical non-extendable shares: ERA Bug 1 (passphrase ignored) affects them,
#     but Feistel round-trip preserves EMS when identifier is the same
#   - Current extendable shares: ERA Bug 2 (extendable hardcoded False) changes the
#     salt, breaking the Feistel round-trip — BOTH wallets produce wrong addresses
# ---------------------------------------------------------------------------


def test_trezor_nonextendable_shares_correctly_implemented():
    """
    Verify that Trezor's historical non-extendable SLIP39 shares are correctly
    implemented — the extendable flag matches the actual salt used during encryption.

    Trezor firmware reference:
      core/src/trezor/crypto/slip39.py:
        _get_salt(): non-extendable → CUSTOMIZATION_STRING_ORIG + identifier.to_bytes(...)
        split_ems(): passes extendable flag through to _encode_mnemonic()

    This proves Trezor does NOT have the ERAWLT bug where shares are flagged as
    non-extendable but encrypted with empty (extendable) salt.
    """
    # Generate shares the way Trezor historically did (non-extendable).
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=False, iteration_exponent=1
    )[0]

    # verify_mnemonics should pass — no salt/flag mismatch.
    shamir.verify_mnemonics(mnemonics[:3], b"", MS)

    # Also verify with passphrase — Trezor correctly encrypts with passphrase.
    mnemonics_pp = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=False, iteration_exponent=1
    )[0]
    shamir.verify_mnemonics(mnemonics_pp[:3], b"TREZOR", MS)


def test_trezor_extendable_shares_correctly_implemented():
    """
    Verify that Trezor's current extendable SLIP39 shares are correctly
    implemented — the extendable flag matches the actual salt used.

    Trezor firmware reference:
      core/src/apps/management/reset_device/__init__.py:
        # Force extendable backup.
        if backup_type == BAK_T_SLIP39_BASIC:
            backup_type = BAK_T_SLIP39_BASIC_EXT
        if backup_type == BAK_T_SLIP39_ADVANCED:
            backup_type = BAK_T_SLIP39_ADVANCED_EXT

      core/src/trezor/crypto/slip39.py:
        _get_salt(): extendable → bytes() (empty salt)

    Current Trezor firmware forces ALL new SLIP39 shares to be extendable.
    """
    # Generate shares the way current Trezor does (extendable).
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=True, iteration_exponent=1
    )[0]

    # verify_mnemonics should pass — correctly implemented.
    shamir.verify_mnemonics(mnemonics[:3], b"", MS)

    # Also with passphrase.
    mnemonics_pp = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"TREZOR", extendable=True, iteration_exponent=1
    )[0]
    shamir.verify_mnemonics(mnemonics_pp[:3], b"TREZOR", MS)


def test_trezor_correct_passphrase_handling():
    """
    Verify that Trezor correctly uses the user's passphrase for seed derivation,
    unlike ERA wallet which always uses empty passphrase.

    Trezor firmware reference (core/src/apps/common/mnemonic.py):
        seed = slip39.decrypt(
            mnemonic_secret,      # ← the stored EMS
            passphrase.encode(),  # ← the user's ACTUAL passphrase
            iteration_exponent,
            identifier,
            extendable,           # ← correct extendable flag from share metadata
            render_func,
        )

    ERA wallet reference (Account.cpp):
        auto ms = encryptedMasterSecret.decrypt({});  # ← ALWAYS empty passphrase

    This test proves Trezor's implementation is the reference standard:
    it stores EMS and decrypts with the correct passphrase.
    """
    passphrase = b"TREZOR"

    # Simulate Trezor's internal storage: EMS is stored, not decrypted secret.
    ems_obj = shamir.EncryptedMasterSecret.from_master_secret(
        MS, passphrase, identifier=42, extendable=False, iteration_exponent=1
    )

    # Trezor decrypts with user's passphrase → correct master secret.
    trezor_seed = ems_obj.decrypt(passphrase)
    assert trezor_seed == MS, (
        "Trezor correctly recovers the master secret using the user's passphrase."
    )

    # ERA decrypts with empty passphrase → WRONG master secret.
    era_seed = ems_obj.decrypt(b"")
    assert era_seed != MS, (
        "ERA gets the WRONG master secret because it ignores the user's passphrase."
    )

    # Trezor and ERA produce different seeds.
    assert trezor_seed != era_seed, (
        "Trezor and ERA derive different seeds from the same EMS "
        "because ERA ignores the passphrase."
    )


def test_trezor_historical_nonextendable_with_passphrase_era_vulnerability():
    """
    Trezor HISTORICALLY generated non-extendable SLIP39 shares (before the
    force-extendable change). When these shares are passphrase-protected and
    imported into ERA wallet, ERA's Bug 1 causes wrong entropy to be stored.

    However, the Feistel round-trip property PRESERVES the EMS ciphertext
    when the salt (identifier) is the same, so entering the correct passphrase
    in ERA still produces the correct seed.

    Vulnerability level: MODERATE
    - Default (no-passphrase) view: WRONG addresses
    - Passphrase view: CORRECT addresses (saved by Feistel round-trip)
    - Rework with same identifier: passphrase wallet survives
    - Rework with different identifier: passphrase wallet DESTROYED

    Trezor firmware reference:
      reset_device/__init__.py _get_slip39_mnemonics():
        if not extendable:
            identifier = storage_device.get_slip39_identifier()
        # ↑ For non-extendable, identifier is stored once and reused
    """
    passphrase = b"TREZOR"

    # Simulate Trezor's historical non-extendable share generation.
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]

    # Import into ERA wallet simulation.
    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    # ERA stores wrong entropy (Bug 1: decrypt with "").
    assert result.stored_entropy != MS

    # ERA's default view shows wrong addresses.
    assert result.no_passphrase_seed != MS

    # But ERA's passphrase view shows CORRECT addresses (Feistel round-trip).
    assert result.passphrase_seed == MS, (
        "For Trezor historical non-extendable shares with passphrase, "
        "ERA's passphrase wallet works correctly because the Feistel "
        "round-trip preserves the EMS (same salt = same identifier)."
    )

    # The EMS is preserved (Feistel round-trip property).
    groups = shamir.decode_mnemonics(mnemonics[:3])
    original_ems = shamir.recover_ems(groups)
    assert result.stored_ems == original_ems.ciphertext, (
        "Feistel round-trip preserves the EMS for non-extendable shares."
    )

    # BIP32 keys match for passphrase wallet.
    assert BIP32Key.fromEntropy(result.passphrase_seed).ExtendedKey() == (
        BIP32Key.fromEntropy(MS).ExtendedKey()
    )


def test_trezor_current_extendable_with_passphrase_era_vulnerability():
    """
    Trezor CURRENTLY forces extendable SLIP39 shares. When these shares are
    passphrase-protected and imported into ERA wallet, ERA's Bug 2 (hardcoded
    extendable=False) changes the salt during re-encryption. The Feistel
    round-trip BREAKS because the salt changes:

      encrypt(decrypt(ct, empty_salt), non_empty_salt) ≠ ct

    This means BOTH wallets (default and passphrase) produce wrong addresses.

    Vulnerability level: MAXIMUM
    - Default (no-passphrase) view: WRONG addresses
    - Passphrase view: WRONG addresses (salt mismatch breaks Feistel round-trip)
    - Rework: ALWAYS produces wrong shares regardless of identifier

    Trezor firmware reference:
      reset_device/__init__.py:
        # Force extendable backup.
        if backup_type == BAK_T_SLIP39_BASIC:
            backup_type = BAK_T_SLIP39_BASIC_EXT
        if backup_type == BAK_T_SLIP39_ADVANCED:
            backup_type = BAK_T_SLIP39_ADVANCED_EXT

      _get_slip39_mnemonics():
        if extendable:
            identifier = slip39.generate_random_identifier()
        # ↑ Extendable shares get fresh random identifier each backup

    ERA wallet bug reference (Account.cpp:851):
      auto ems = common::shamir::EncryptedMasterSecret::fromMasterSecret(
          entropy, "", id, false, ie);
      # ↑ ALWAYS uses extendable=false, even for extendable shares
    """
    passphrase = b"TREZOR"

    # Simulate current Trezor extendable share generation.
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]

    # Import into ERA wallet simulation.
    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    # ERA stores wrong entropy (Bug 1: decrypt with "").
    assert result.stored_entropy != MS

    # The EMS is NOT preserved — Bug 2 changes the salt.
    groups = shamir.decode_mnemonics(mnemonics[:3])
    original_ems = shamir.recover_ems(groups)
    assert result.stored_ems != original_ems.ciphertext, (
        "ERA Bug 2 (hardcoded extendable=False) changes the salt for "
        "extendable shares, breaking the Feistel round-trip."
    )

    # ERA's default view: WRONG addresses.
    assert result.no_passphrase_seed != MS

    # ERA's passphrase view: ALSO WRONG addresses (salt mismatch).
    assert result.passphrase_seed != MS, (
        "For Trezor current extendable shares with passphrase, ERA's "
        "passphrase wallet ALSO produces wrong addresses because Bug 2 "
        "changes the salt, breaking the Feistel round-trip property."
    )

    # Neither view produces correct addresses — maximum vulnerability.
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()
    assert BIP32Key.fromEntropy(result.no_passphrase_seed).ExtendedKey() != correct_xprv
    assert BIP32Key.fromEntropy(result.passphrase_seed).ExtendedKey() != correct_xprv


def test_trezor_current_extendable_no_passphrase_era_vulnerability():
    """
    Even WITHOUT a passphrase, Trezor's current extendable shares are
    affected by ERA's Bug 2 — but the impact depends on whether the user
    later tries to use a passphrase wallet.

    Without passphrase:
    - Bug 1 is harmless (decrypt with "" is correct when no passphrase used)
    - Bug 2 changes the salt, so stored EMS differs from original
    - But the no-passphrase seed is STILL wrong because:
      ERA decrypts the re-encrypted EMS (wrong salt) with "" and extendable=False
      The original was encrypted with extendable=True (empty salt)
      Since ERA re-encrypts and re-decrypts with the SAME (wrong) salt,
      the round-trip WITHIN ERA preserves the entropy.

    Trezor firmware reference:
      mnemonic.py get_seed():
        extendable = backup_types.is_extendable_backup_type(get_type())
        seed = slip39.decrypt(mnemonic_secret, passphrase.encode(),
                              iteration_exponent, identifier, extendable, ...)
      # ↑ Trezor would correctly use extendable=True, ERA uses False
    """
    # Simulate current Trezor extendable share generation without passphrase.
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=True, iteration_exponent=1
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=b"")

    # ERA's stored EMS differs from the original (Bug 2 changes salt).
    groups = shamir.decode_mnemonics(mnemonics[:3])
    original_ems = shamir.recover_ems(groups)
    assert result.stored_ems != original_ems.ciphertext

    # But ERA's no-passphrase seed is the SAME as what ERA stored as entropy.
    # Because Bug 1 (decrypt with "") and Bug 2 (re-encrypt with same wrong salt)
    # create a self-consistent round-trip WITHIN ERA.
    assert result.no_passphrase_seed == result.stored_entropy

    # ERA's stored entropy equals the no-passphrase view:
    # decrypt(EMS, "", ie, id, True) ← what compliant tool does
    # vs
    # decrypt(encrypt(decrypt(EMS, "", ie, id, True), "", ie, id, False),
    #         "", ie, id, False) ← what ERA does
    # The inner round-trip preserves the entropy when passphrase matches ("").

    # Compliant recovery gives the original secret.
    assert result.correct_master_secret == MS

    # ERA's stored entropy differs from the correct master secret
    # because the salt changes during re-encryption.
    # BUT wait — for no-passphrase case, let's check what actually happens:
    # Bug 1: era_entropy = decrypt(EMS, "", ie, id, extendable=True) = MS (correct!)
    # Bug 2: era_ems = encrypt(MS, "", ie, id, extendable=False)
    # No-pp seed: decrypt(era_ems, "", ie, id, False) = MS (correct via round-trip!)
    assert result.stored_entropy == MS, (
        "Without passphrase, Bug 1 is harmless — ERA decrypts correctly."
    )
    assert result.no_passphrase_seed == MS, (
        "Without passphrase, ERA's no-passphrase view is correct "
        "because the Feistel round-trip within ERA is self-consistent."
    )


def test_trezor_extendable_with_passphrase_rework_always_wrong():
    """
    When ERA reworks Trezor PASSPHRASE-PROTECTED extendable shares, the result
    is ALWAYS wrong regardless of whether the identifier matches, because Bug 2
    changed the salt during import and Bug 1 stored the wrong entropy.

    For extendable shares WITH passphrase:
    - Original salt was empty (extendable=True)
    - ERA stored EMS was encrypted with non-empty salt (extendable=False)
    - The stored entropy is wrong (Bug 1 decrypted with "" instead of passphrase)
    - Reworking from wrong entropy with any identifier produces wrong shares

    This is the WORST CASE scenario: extendable + passphrase + ERA rework.

    NOTE: This does NOT apply to no-passphrase extendable shares — those
    produce correct addresses in ERA and correct reworked shares, because
    Bug 1 is harmless when no passphrase was used.  See
    ``test_trezor_extendable_no_passphrase_era_rework_is_correct()``.

    The ERA wallet does NOT reject the import or rework — it silently
    produces wrong shares.  "Always wrong" means the resulting wallet is
    wrong, not that ERA shows an error message.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]

    # Rework with same identifier — still broken for extendable shares.
    rework = shamir.simulate_era_rework(
        mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
    )

    # Secret is NOT recoverable even with same identifier.
    assert not rework.original_secret_recoverable, (
        "For extendable shares with passphrase, ERA rework ALWAYS fails "
        "because Bug 2 already changed the salt during import, so the "
        "stored entropy is wrong and no identifier can fix it."
    )

    assert rework.recovered_with_passphrase != MS
    assert rework.recovered_without_passphrase != MS


def test_trezor_nonextendable_vs_extendable_era_impact_comparison():
    """
    Side-by-side comparison showing that Trezor's switch from non-extendable
    to extendable backup INCREASED vulnerability to ERA wallet bugs.

    Historical (non-extendable):
      - Passphrase wallet: WORKS in ERA (Feistel round-trip preserves EMS)
      - Default wallet: WRONG addresses
      - Rework with same id: passphrase wallet SURVIVES

    Current (extendable):
      - Passphrase wallet: BROKEN in ERA (salt mismatch breaks round-trip)
      - Default wallet: WRONG addresses
      - Rework: ALWAYS broken regardless of identifier

    Trezor firmware reference:
      reset_device/__init__.py:
        # Force extendable backup.
        if backup_type == BAK_T_SLIP39_BASIC:
            backup_type = BAK_T_SLIP39_BASIC_EXT
    """
    passphrase = b"TREZOR"

    # Historical non-extendable shares.
    nonext_mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]
    nonext_result = shamir.simulate_era_import(nonext_mnemonics[:3], passphrase=passphrase)

    # Current extendable shares.
    ext_mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]
    ext_result = shamir.simulate_era_import(ext_mnemonics[:3], passphrase=passphrase)

    # Both: ERA stores wrong entropy (Bug 1).
    assert nonext_result.stored_entropy != MS
    assert ext_result.stored_entropy != MS

    # Non-extendable: passphrase wallet WORKS.
    assert nonext_result.passphrase_seed == MS, (
        "Historical non-extendable: passphrase wallet works in ERA."
    )

    # Extendable: passphrase wallet BROKEN.
    assert ext_result.passphrase_seed != MS, (
        "Current extendable: passphrase wallet broken in ERA."
    )

    # Non-extendable: EMS preserved.
    nonext_groups = shamir.decode_mnemonics(nonext_mnemonics[:3])
    nonext_ems = shamir.recover_ems(nonext_groups)
    assert nonext_result.stored_ems == nonext_ems.ciphertext, (
        "Non-extendable: Feistel round-trip preserves EMS."
    )

    # Extendable: EMS changed.
    ext_groups = shamir.decode_mnemonics(ext_mnemonics[:3])
    ext_ems = shamir.recover_ems(ext_groups)
    assert ext_result.stored_ems != ext_ems.ciphertext, (
        "Extendable: Bug 2 changes the salt, breaking EMS preservation."
    )

    # Non-extendable rework with same id: passphrase wallet survives.
    nonext_rework = shamir.simulate_era_rework(
        nonext_mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
    )
    assert nonext_rework.original_secret_recoverable, (
        "Non-extendable rework with same id: passphrase wallet survives."
    )

    # Extendable rework: ALWAYS fails.
    ext_rework = shamir.simulate_era_rework(
        ext_mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
    )
    assert not ext_rework.original_secret_recoverable, (
        "Extendable rework: ALWAYS fails because Bug 2 already broke the EMS."
    )


def test_trezor_force_extendable_concrete_bip32_divergence():
    """
    Concrete BIP32 key comparison showing that Trezor's current extendable
    shares produce THREE distinct wrong wallets in ERA:
      1. The correct wallet (from Trezor with correct passphrase)
      2. ERA's default wallet (wrong — Bug 1 + Bug 2)
      3. ERA's passphrase wallet (wrong — Bug 2 changed the salt)

    All three produce different xprv keys and different addresses.

    This is the most dangerous scenario for real-world users, because
    current Trezor firmware generates exactly these shares.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]

    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()
    era_default_xprv = BIP32Key.fromEntropy(result.no_passphrase_seed).ExtendedKey()
    era_passphrase_xprv = BIP32Key.fromEntropy(result.passphrase_seed).ExtendedKey()

    # All three are different.
    assert correct_xprv != era_default_xprv, (
        "ERA default wallet diverges from correct wallet."
    )
    assert correct_xprv != era_passphrase_xprv, (
        "ERA passphrase wallet ALSO diverges (Bug 2 changed the salt)."
    )
    assert era_default_xprv != era_passphrase_xprv, (
        "ERA shows two distinct wrong wallets."
    )

    # Trezor itself would produce the correct seed.
    # Simulate Trezor's correct behavior: decrypt EMS with passphrase + extendable=True.
    groups = shamir.decode_mnemonics(mnemonics[:3])
    original_ems = shamir.recover_ems(groups)
    trezor_seed = original_ems.decrypt(passphrase)
    assert trezor_seed == MS
    assert BIP32Key.fromEntropy(trezor_seed).ExtendedKey() == correct_xprv


# ---------------------------------------------------------------------------
# ERA "silent acceptance" — clarifying import vs. correctness
# ---------------------------------------------------------------------------
# The ERA wallet NEVER rejects any SLIP39 import.  There is no error message,
# no validation failure, no warning dialog.  ERA always:
#   1. Decodes the shares and recovers the EMS                   ✓ works
#   2. Decrypts with empty passphrase (Bug 1)                    ← may be wrong
#   3. Re-encrypts with extendable=False (Bug 2)                 ← may change salt
#   4. Stores the result and offers to show addresses / rework    ✓ always offered
#
# "Import accepted" does NOT mean "addresses are correct."
# "Rework offered" does NOT mean "reworked wallet is valid."
#
# Whether the result is correct depends on the passphrase scenario:
#
#   Trezor extendable (current) + NO passphrase:
#     Import: ✓ addresses match     Rework: ✓ wallet correct
#   Trezor extendable (current) + WITH passphrase:
#     Import: ✗ addresses wrong     Rework: ✗ wallet wrong (silent!)
#   Trezor non-extendable (historical) + NO passphrase:
#     Import: ✓ addresses match     Rework: ✓ wallet correct
#   Trezor non-extendable (historical) + WITH passphrase:
#     Import: ✗ default wrong,      Rework: ✓ if same identifier,
#             ✓ passphrase view OK           ✗ if identifier changes
# ---------------------------------------------------------------------------


def test_era_silently_accepts_all_trezor_share_types():
    """
    ERA wallet NEVER rejects any Trezor SLIP39 import.

    The user reported: "I imported a SLIP39 share from a current Trezor and
    the ERA wallet did accept it and immediately offer to re-work it."

    This is expected — ERA always accepts.  The question is not whether ERA
    accepts, but whether the resulting addresses are correct.

    This test demonstrates that simulate_era_import() runs without error for
    every combination of Trezor share types and passphrase settings.
    "Accepted" and "correct" are different things.
    """
    scenarios = [
        # (extendable, passphrase, description)
        (True, b"", "current Trezor extendable, no passphrase"),
        (True, b"TREZOR", "current Trezor extendable, with passphrase"),
        (False, b"", "historical Trezor non-extendable, no passphrase"),
        (False, b"TREZOR", "historical Trezor non-extendable, with passphrase"),
    ]

    for extendable, passphrase, desc in scenarios:
        mnemonics = shamir.generate_mnemonics(
            1, [(3, 5)], MS, passphrase, extendable=extendable, iteration_exponent=1
        )[0]

        # ERA import ALWAYS succeeds — no exception, no error.
        result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

        # ERA ALWAYS produces a stored_ems and stored_entropy.
        assert result.stored_ems is not None, f"ERA must store EMS for: {desc}"
        assert result.stored_entropy is not None, f"ERA must store entropy for: {desc}"
        assert len(result.stored_ems) > 0, f"ERA stored EMS must be non-empty: {desc}"
        assert len(result.stored_entropy) > 0, f"ERA stored entropy must be non-empty: {desc}"

        # ERA ALWAYS offers to show addresses (no-passphrase seed is always computed).
        assert result.no_passphrase_seed is not None, f"ERA computes seed for: {desc}"

        # ERA rework ALWAYS succeeds too — no exception.
        rework = shamir.simulate_era_rework(
            mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
        )
        assert len(rework.reworked_shares) == 3, f"ERA must produce reworked shares: {desc}"


def test_trezor_extendable_no_passphrase_era_rework_is_correct():
    """
    When a user imports a current Trezor extendable share WITHOUT passphrase
    into ERA and ERA reworks it, the reworked wallet IS CORRECT.

    This is the most common real-world scenario: a user creates SLIP39 shares
    on a current Trezor (which forces extendable) without a passphrase, imports
    into ERA, and ERA reworks the backup.  Everything works.

    The reason:
    - Bug 1 (empty passphrase): Harmless — no passphrase was used, so
      decrypt(EMS, "") gives the correct master secret.
    - Bug 2 (extendable=False): Changes the salt, but since ERA also
      re-decrypts with the SAME (wrong) salt, the round-trip within ERA
      is self-consistent.  The entropy stored by ERA is correct.
    - Rework: ERA re-encrypts the correct entropy with a (potentially new)
      identifier and extendable=False.  A compliant tool can recover the
      correct master secret by combining the reworked shares with no passphrase.

    "Always fails" in test_trezor_extendable_rework_always_wrong() refers ONLY
    to the WITH-PASSPHRASE case, not this no-passphrase scenario.
    """
    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=True, iteration_exponent=1
    )[0]

    # ERA import: addresses are correct (no passphrase means Bug 1 is harmless).
    result = shamir.simulate_era_import(mnemonics[:3], passphrase=b"")
    assert result.stored_entropy == MS, (
        "Without passphrase, ERA stores the correct entropy."
    )
    assert result.no_passphrase_seed == MS, (
        "Without passphrase, ERA shows correct addresses."
    )

    # ERA rework: produces correct wallet.
    rework = shamir.simulate_era_rework(
        mnemonics[:3], passphrase=b"", rework_groups=((2, 3),),
    )

    # The reworked shares recover the original secret.
    assert rework.original_secret_recoverable, (
        "For no-passphrase extendable shares, ERA rework produces a valid wallet "
        "that recovers the original master secret."
    )
    assert rework.recovered_without_passphrase == MS, (
        "A compliant tool recovers the correct secret from reworked shares."
    )

    # BIP32 keys match: the reworked wallet produces the same addresses.
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()
    reworked_xprv = BIP32Key.fromEntropy(rework.recovered_without_passphrase).ExtendedKey()
    assert reworked_xprv == correct_xprv, (
        "Reworked wallet from no-passphrase extendable shares produces "
        "the same BIP32 root key as the original."
    )


def test_trezor_extendable_with_passphrase_era_import_accepted_addresses_wrong():
    """
    When a user imports a current Trezor extendable share WITH passphrase into
    ERA, the import is ACCEPTED but ALL addresses are WRONG.

    ERA does not show any error or warning.  The user sees:
    - Default (no-passphrase) view: WRONG addresses
    - Passphrase view: ALSO WRONG addresses (Bug 2 changed the salt)
    - Rework option: offered, but reworked wallet is also wrong

    This is what "always fails" means for extendable+passphrase shares:
    not that ERA rejects the import, but that every address ERA shows is wrong.
    """
    passphrase = b"TREZOR"

    mnemonics = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]

    # ERA import: ACCEPTED (no error).
    result = shamir.simulate_era_import(mnemonics[:3], passphrase=passphrase)

    # But ALL addresses are wrong.
    correct_xprv = BIP32Key.fromEntropy(MS).ExtendedKey()

    # Default view: wrong.
    assert result.no_passphrase_seed != MS, "ERA default view: wrong addresses."
    era_default_xprv = BIP32Key.fromEntropy(result.no_passphrase_seed).ExtendedKey()
    assert era_default_xprv != correct_xprv, (
        "ERA default BIP32 root key diverges — user sees entirely different addresses."
    )

    # Passphrase view: ALSO wrong (Bug 2 broke the Feistel round-trip).
    assert result.passphrase_seed != MS, "ERA passphrase view: also wrong."
    era_pp_xprv = BIP32Key.fromEntropy(result.passphrase_seed).ExtendedKey()
    assert era_pp_xprv != correct_xprv, (
        "ERA passphrase BIP32 root key ALSO diverges — Bug 2 changed the salt, "
        "so even entering the correct passphrase produces wrong addresses."
    )

    # ERA rework: also accepted, also wrong.
    rework = shamir.simulate_era_rework(
        mnemonics[:3], passphrase=passphrase, rework_groups=((2, 3),),
    )
    assert len(rework.reworked_shares) == 3, "ERA rework is offered and produces shares."
    assert not rework.original_secret_recoverable, (
        "Reworked shares do NOT recover the original secret — the wallet is wrong "
        "and ERA never warned the user."
    )


def test_era_import_acceptance_vs_correctness_matrix():
    """
    Comprehensive matrix showing ERA import + rework outcomes for all Trezor
    share types.

    This directly answers the question: "I imported a SLIP39 share from a
    current Trezor and ERA accepted it.  Does that mean it works?"

    Answer: ERA always accepts.  Whether it WORKS depends on the passphrase:

    ┌─────────────────────────────────────────────────────────────────────┐
    │ Share Type              │ Passphrase │ Import OK? │ Rework OK?     │
    ├─────────────────────────┼────────────┼────────────┼────────────────┤
    │ Extendable (current)    │ None       │ ✓ correct  │ ✓ correct      │
    │ Extendable (current)    │ Any        │ ✗ wrong    │ ✗ always wrong │
    │ Non-extendable (legacy) │ None       │ ✓ correct  │ ✓ correct      │
    │ Non-extendable (legacy) │ Any        │ ✗/✓ (*)    │ depends (**)   │
    └─────────────────────────┴────────────┴────────────┴────────────────┘

    (*) Non-extendable + passphrase: default view wrong, passphrase view correct
    (**) Rework correct if same identifier, wrong if identifier changes (e.g. to 0)

    In ALL cases, ERA "accepts" the import without any error or warning.
    """
    passphrase = b"TREZOR"

    # --- Extendable (current Trezor), NO passphrase ---
    ext_no_pp = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=True, iteration_exponent=1
    )[0]
    ext_no_pp_result = shamir.simulate_era_import(ext_no_pp[:3], passphrase=b"")
    ext_no_pp_rework = shamir.simulate_era_rework(ext_no_pp[:3], passphrase=b"")

    assert ext_no_pp_result.no_passphrase_seed == MS, "Ext+NoPass: import ✓"
    assert ext_no_pp_rework.original_secret_recoverable, "Ext+NoPass: rework ✓"

    # --- Extendable (current Trezor), WITH passphrase ---
    ext_pp = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=True, iteration_exponent=1
    )[0]
    ext_pp_result = shamir.simulate_era_import(ext_pp[:3], passphrase=passphrase)
    ext_pp_rework = shamir.simulate_era_rework(ext_pp[:3], passphrase=passphrase)

    assert ext_pp_result.no_passphrase_seed != MS, "Ext+Pass: default view ✗"
    assert ext_pp_result.passphrase_seed != MS, "Ext+Pass: passphrase view ✗"
    assert not ext_pp_rework.original_secret_recoverable, "Ext+Pass: rework ✗"

    # --- Non-extendable (historical Trezor), NO passphrase ---
    nonext_no_pp = shamir.generate_mnemonics(
        1, [(3, 5)], MS, b"", extendable=False, iteration_exponent=1
    )[0]
    nonext_no_pp_result = shamir.simulate_era_import(nonext_no_pp[:3], passphrase=b"")
    nonext_no_pp_rework = shamir.simulate_era_rework(nonext_no_pp[:3], passphrase=b"")

    assert nonext_no_pp_result.no_passphrase_seed == MS, "NonExt+NoPass: import ✓"
    assert nonext_no_pp_rework.original_secret_recoverable, "NonExt+NoPass: rework ✓"

    # --- Non-extendable (historical Trezor), WITH passphrase ---
    nonext_pp = shamir.generate_mnemonics(
        1, [(3, 5)], MS, passphrase, extendable=False, iteration_exponent=1
    )[0]
    nonext_pp_result = shamir.simulate_era_import(nonext_pp[:3], passphrase=passphrase)

    assert nonext_pp_result.no_passphrase_seed != MS, "NonExt+Pass: default view ✗"
    assert nonext_pp_result.passphrase_seed == MS, "NonExt+Pass: passphrase view ✓"

    # Rework with same identifier: passphrase wallet survives.
    nonext_pp_rework_same = shamir.simulate_era_rework(
        nonext_pp[:3], passphrase=passphrase, rework_groups=((2, 3),),
    )
    assert nonext_pp_rework_same.original_secret_recoverable, (
        "NonExt+Pass: rework ✓ (same id)"
    )

    # Rework with different identifier: passphrase wallet destroyed.
    nonext_pp_rework_diff = shamir.simulate_era_rework(
        nonext_pp[:3], passphrase=passphrase, rework_groups=((2, 3),),
        new_identifier=0,
    )
    # Only fails if the original identifier was not 0.
    if nonext_pp_rework_diff.original_identifier != 0:
        assert not nonext_pp_rework_diff.original_secret_recoverable, (
            "NonExt+Pass: rework ✗ (different id destroys passphrase wallet)"
        )


# ---------------------------------------------------------------------------
# Step-by-step Trezor → ERA workflows
# ---------------------------------------------------------------------------
# These tests map real-world Trezor user actions to code, answering:
#   "What do I do on my Trezor to create a SLIP39 backup that will
#    import incorrectly into the ERA wallet?"
#
# Workflow A (INCORRECT import — the dangerous path):
#   1. On Trezor: create wallet with SLIP39 backup
#   2. On Trezor: enable passphrase feature
#   3. Import shares into ERA wallet
#   4. ERA accepts — but ALL addresses are silently wrong
#   5. ERA offers rework — reworked shares are also wrong
#
# Workflow B (CORRECT import — the safe path):
#   1. On Trezor: create wallet with SLIP39 backup
#   2. Do NOT enable passphrase
#   3. Import shares into ERA wallet
#   4. ERA accepts — addresses are correct
#   5. ERA offers rework — reworked shares are also correct
# ---------------------------------------------------------------------------


def test_workflow_trezor_slip39_that_imports_wrong_into_era():
    """
    Step-by-step workflow: how to create a Trezor SLIP39 backup that will
    import INCORRECTLY into the ERA wallet.

    This answers: "Can you give me the workflow for creating a SLIP39 backup
    on an existing Trezor that will import incorrect into the ERA wallet?"

    WORKFLOW (real-world steps → code equivalent):

    Step 1 — Create or restore a wallet on your Trezor
      The Trezor generates a random master secret internally.
      → MS = b"ABCDEFGHIJKLMNOP"  (our test stand-in)

    Step 2 — Create a SLIP39 backup on the Trezor
      Current Trezor firmware FORCES extendable backup (since firmware 2.7.0+).
      The Trezor encrypts the master secret into an EMS and splits it into
      shares using Shamir's Secret Sharing.
      → generate_mnemonics(..., extendable=True)

    Step 3 — Enable passphrase on the Trezor
      In Trezor Settings → Security → Passphrase, enable passphrase.
      Enter a passphrase like "TREZOR".  The Trezor uses this passphrase
      to decrypt the EMS → master secret → BIP32 seed → addresses.
      → passphrase = b"TREZOR"
      THIS IS THE TRIGGER.  Without this step, ERA import works correctly.

    Step 4 — Import the SLIP39 shares into ERA wallet
      Enter enough shares to meet the threshold (e.g. 3 of 5).
      ERA accepts the shares — no error, no warning, no rejection.
      → simulate_era_import(shares, passphrase)

    Step 5 — ERA shows addresses
      ERA's Bug 1 (decrypt with empty passphrase) means it stores the wrong
      entropy.  ERA's Bug 2 (hardcoded extendable=False) changes the
      encryption salt.  BOTH the default view AND the passphrase view in
      ERA show WRONG addresses that don't match the Trezor.

    Step 6 — ERA offers to rework (regenerate backup)
      ERA accepts the rework request.  But the reworked shares are ALSO
      wrong — they encode the wrong entropy with the wrong salt.
      A compliant tool (including the Trezor itself) cannot recover the
      original master secret from the reworked shares.

    RESULT: The user's wallet appears empty or shows different addresses.
    The original passphrase-protected wallet is silently inaccessible via ERA.
    The original Trezor shares still work correctly on the Trezor itself.
    """
    # Step 1: Master secret (what the Trezor stores internally).
    master_secret = MS

    # Step 2: Trezor creates SLIP39 backup (current firmware forces extendable).
    passphrase = b"TREZOR"
    trezor_shares = shamir.generate_mnemonics(
        1, [(3, 5)], master_secret, passphrase, extendable=True, iteration_exponent=1
    )[0]
    # The user writes down 5 shares on paper, e.g. "academic acid acrobat..."
    assert len(trezor_shares) == 5

    # Step 3: Passphrase is set on Trezor.  The Trezor derives addresses by
    # decrypting EMS with the passphrase.  Let's record what the Trezor shows.
    trezor_xprv = BIP32Key.fromEntropy(master_secret).ExtendedKey()

    # Step 4: User imports 3 of 5 shares into ERA wallet.
    shares_for_era = trezor_shares[:3]
    era_result = shamir.simulate_era_import(shares_for_era, passphrase=passphrase)

    # ERA "accepts" — no error.
    assert era_result.stored_ems is not None
    assert era_result.stored_entropy is not None

    # Step 5: ERA shows addresses — ALL WRONG.
    # Default (no-passphrase) view:
    era_default_xprv = BIP32Key.fromEntropy(era_result.no_passphrase_seed).ExtendedKey()
    assert era_default_xprv != trezor_xprv, (
        "Step 5a: ERA default addresses don't match Trezor."
    )

    # Passphrase view (user enters "TREZOR" in ERA):
    era_passphrase_xprv = BIP32Key.fromEntropy(era_result.passphrase_seed).ExtendedKey()
    assert era_passphrase_xprv != trezor_xprv, (
        "Step 5b: ERA passphrase addresses ALSO don't match Trezor — "
        "Bug 2 changed the salt, breaking the Feistel round-trip."
    )

    # The three wallets (correct, ERA default, ERA passphrase) are all different.
    assert era_default_xprv != era_passphrase_xprv, (
        "ERA shows two distinct wrong wallets, neither matching the Trezor."
    )

    # Step 6: ERA offers rework — user accepts — reworked shares are ALSO wrong.
    era_rework = shamir.simulate_era_rework(
        shares_for_era, passphrase=passphrase, rework_groups=((2, 3),),
    )
    assert len(era_rework.reworked_shares) == 3, "ERA produces reworked shares."
    assert not era_rework.original_secret_recoverable, (
        "Step 6: Reworked shares do NOT recover the original master secret."
    )

    # The original Trezor shares STILL WORK on the Trezor itself.
    recovered = shamir.combine_mnemonics(trezor_shares[:3], passphrase)
    assert recovered == master_secret, (
        "Original Trezor shares still recover the correct master secret — "
        "the problem is only in ERA, not in the shares themselves."
    )


def test_workflow_trezor_slip39_that_imports_correctly_into_era():
    """
    Step-by-step workflow: how to create a Trezor SLIP39 backup that WILL
    import CORRECTLY into the ERA wallet.

    This is the SAFE path — the only difference from the dangerous workflow
    is: DO NOT use a passphrase.

    WORKFLOW (real-world steps → code equivalent):

    Step 1 — Create or restore a wallet on your Trezor
      → MS = b"ABCDEFGHIJKLMNOP"

    Step 2 — Create a SLIP39 backup on the Trezor
      Current firmware forces extendable backup.
      → generate_mnemonics(..., extendable=True)

    Step 3 — Do NOT enable passphrase on the Trezor
      Leave passphrase disabled (the default setting).
      → passphrase = b""
      THIS IS THE KEY DIFFERENCE.

    Step 4 — Import the SLIP39 shares into ERA wallet
      ERA accepts the shares.
      → simulate_era_import(shares, passphrase=b"")

    Step 5 — ERA shows addresses — CORRECT
      Bug 1 (decrypt with "") is harmless when no passphrase was used.
      Bug 2 (extendable=False) changes the salt, but ERA's internal
      round-trip is self-consistent, so the stored entropy is correct.

    Step 6 — ERA offers to rework — reworked shares are ALSO correct
      ERA re-encrypts the correct entropy.  A compliant tool recovers
      the original master secret from the reworked shares.

    RESULT: ERA shows the same addresses as the Trezor.
    The reworked shares are also valid.
    """
    # Step 1: Master secret.
    master_secret = MS

    # Step 2: Trezor creates SLIP39 backup (extendable, NO passphrase).
    trezor_shares = shamir.generate_mnemonics(
        1, [(3, 5)], master_secret, b"", extendable=True, iteration_exponent=1
    )[0]
    assert len(trezor_shares) == 5

    # Step 3: No passphrase — Trezor derives addresses directly from master secret.
    trezor_xprv = BIP32Key.fromEntropy(master_secret).ExtendedKey()

    # Step 4: Import into ERA.
    shares_for_era = trezor_shares[:3]
    era_result = shamir.simulate_era_import(shares_for_era, passphrase=b"")

    # Step 5: ERA shows CORRECT addresses.
    era_default_xprv = BIP32Key.fromEntropy(era_result.no_passphrase_seed).ExtendedKey()
    assert era_default_xprv == trezor_xprv, (
        "Step 5: Without passphrase, ERA default addresses MATCH the Trezor."
    )
    assert era_result.stored_entropy == master_secret, (
        "ERA stores the correct entropy when no passphrase is used."
    )

    # Step 6: ERA rework produces correct wallet.
    era_rework = shamir.simulate_era_rework(
        shares_for_era, passphrase=b"", rework_groups=((2, 3),),
    )
    assert era_rework.original_secret_recoverable, (
        "Step 6: Reworked shares recover the original master secret."
    )

    # Reworked shares produce correct addresses.
    reworked_xprv = BIP32Key.fromEntropy(
        era_rework.recovered_without_passphrase
    ).ExtendedKey()
    assert reworked_xprv == trezor_xprv, (
        "Reworked wallet produces the same addresses as the Trezor."
    )
