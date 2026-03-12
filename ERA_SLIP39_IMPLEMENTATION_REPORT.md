# ERA Wallet SLIP39 Implementation Report

## Analysis of SLIP39 Bugs in the ERA Wallet (ERAWLT)

**Repository analysed:** [`ERAWLT/ERA-crypto-p`](https://github.com/ERAWLT/ERA-crypto-p/tree/1504ed05ae4cc90128e679f48afc2a6de6fb963a)
(specifically [`Account.cpp`](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp) and [`CryptoModule.cpp`](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp))

**Date:** March 2026

**Reproduction code:**
[github.com/3rdIteration/python-shamir-mnemonic](https://github.com/3rdIteration/python-shamir-mnemonic) — `simulate_era_import()` and `simulate_era_rework()` model ERA's exact code paths.

---

## Executive Summary

The ERA wallet's SLIP39 implementation contains **two bugs** that cause it to
silently produce **wrong cryptocurrency addresses** when importing shares from
standard-compliant devices (e.g. Trezor).  The bugs make ERA's implementation
incompatible with both the **older non-extendable SLIP39 standard** and the
**newer extendable SLIP39 standard** — it implements a custom hybrid that is
only fully compatible with other ERA wallet instances running the same code.

The impact ranges from **silently wrong addresses** (user sees different
addresses than their hardware wallet) to **apparent fund loss** when a user
discards original shares and keeps only ERA-regenerated shares.  However,
**recovery is possible**: because ERA preserves the correct no-passphrase
master secret, the passphrase wallet can be mathematically reconstructed
from ERA-mangled shares — see [Section 10](#10-recovery-getting-your-passphrase-wallet-back).

---

## Table of Contents

1. [Background: How SLIP39 Works](#1-background-how-slip39-works)
2. [The Two Bugs](#2-the-two-bugs)
3. [Why ERA Implements Neither Standard](#3-why-era-implements-neither-standard)
4. [Impact Matrix](#4-impact-matrix)
5. [Confirmed Real-World Scenarios](#5-confirmed-real-world-scenarios)
6. [The Feistel Round-Trip Property](#6-the-feistel-round-trip-property)
7. [ERA Share Rework (Backup Regeneration)](#7-era-share-rework-backup-regeneration)
8. [Cross-Device Compatibility](#8-cross-device-compatibility)
9. [Detailed Code Analysis](#9-detailed-code-analysis)
10. [Recovery: Getting Your Passphrase Wallet Back](#10-recovery-getting-your-passphrase-wallet-back)
11. [Recommendations](#11-recommendations)

---

## 1. Background: How SLIP39 Works

[SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
defines Shamir's Secret Sharing for cryptocurrency seed backup.  The core
cryptographic flow is:

```
Master Secret (MS)
       │
       ▼
encrypt(MS, passphrase, iteration_exponent, identifier, extendable)
       │
       ▼
Encrypted Master Secret (EMS)   ←── this is what's split into shares
       │
       ▼
split into shares via Shamir's Secret Sharing
       │
       ▼
SLIP39 Mnemonic Shares (the words the user writes down)
```

To recover the wallet:

```
SLIP39 Mnemonic Shares (threshold number)
       │
       ▼
Shamir Secret Sharing recovery
       │
       ▼
Encrypted Master Secret (EMS)
       │
       ▼
decrypt(EMS, passphrase, iteration_exponent, identifier, extendable)
       │
       ▼
Master Secret (MS)   ←── used to derive all cryptocurrency keys/addresses
```

### Key Parameters

| Parameter | Role |
|-----------|------|
| **Passphrase** | User-chosen secret; used as input to the Feistel cipher during encrypt/decrypt. Empty string `""` if no passphrase. |
| **Identifier** | Random 15-bit value embedded in shares; used as part of the Feistel cipher salt (for non-extendable) or omitted from salt (for extendable). |
| **Extendable flag** | Determines how the Feistel cipher salt is computed. |
| **Iteration exponent** | Controls PBKDF2 iteration count in the Feistel cipher. |

### The Salt Computation

The `extendable` flag directly controls the Feistel cipher salt:

```python
def _get_salt(identifier, extendable):
    if extendable:
        return bytes()                    # Empty salt
    return b"shamir" + identifier_bytes   # Non-empty salt including identifier
```

This means **extendable and non-extendable shares produce completely different
ciphertexts** from the same master secret, even with identical passphrase and
identifier.  Treating an extendable share as non-extendable (or vice versa)
produces a **different master secret** — and therefore different
cryptocurrency addresses.

---

## 2. The Two Bugs

### Bug 1: Passphrase Ignored During Import

**Location:** `Account.cpp` — [`decodeShamirShares()` line 210](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L210) and [`addAccount()` line 433](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L433)

When ERA imports SLIP39 shares, it recovers the EMS correctly via Shamir's
Secret Sharing.  However, it then **always decrypts the EMS with an empty
passphrase**, regardless of any passphrase the user may have set:

```cpp
// Account.cpp — decodeShamirShares() line 210
// https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L210
auto masterSecret = encryptedMasterSecret.decrypt({});
//                                                ^^
//                           Always empty — user passphrase is IGNORED

// Account.cpp — addAccount() line 433
// https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L433
auto masterSecret = encryptedMasterSecret.decrypt("");
//                                                ^^
//                           Same bug — passphrase parameter never forwarded
```

**What should happen:** The passphrase should be forwarded to the `decrypt()`
call so the correct master secret is recovered.

**What actually happens:** The user's passphrase is accepted by the ERA UI
but silently discarded during import.  The "entropy" ERA stores internally
is the result of decrypting the EMS with an empty passphrase — which is
**wrong** for any passphrase-protected share.

### Bug 2: Extendable Flag Hardcoded to `false`

**Location:** [`Account.cpp` line 851](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L851)

When ERA re-encrypts the (potentially wrong) entropy for internal storage,
it **always uses `extendable=false`**, regardless of whether the imported
shares were extendable or not:

```cpp
// Account.cpp — Account constructor, line 850-851
// https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L850-L851
auto ems = EncryptedMasterSecret::fromMasterSecret(
    entropy, "", identifier, false, iterationExponent
);
//                           ^^^^^
//                    Always false — extendable flag is HARDCODED
```

**What should happen:** The original `extendable` flag from the imported
shares should be preserved.

**What actually happens:** Extendable shares (which use an empty Feistel
salt) are re-encrypted as non-extendable (which uses
`"shamir" + identifier` as the salt).  This **changes the Feistel salt**,
breaking the round-trip property and producing a different EMS ciphertext.

---

## 3. Why ERA Implements Neither Standard

The user's observation is precise: ERA's implementation is a **custom hybrid**
that matches neither the older non-extendable SLIP39 specification nor the
newer extendable specification.

### Comparison Table

| Behaviour | Non-Extendable Standard | Extendable Standard | ERA Wallet |
|-----------|------------------------|--------------------|--------------------|
| **Passphrase during decrypt** | Uses user passphrase | Uses user passphrase | ✗ Always uses `""` (Bug 1) |
| **Extendable flag during re-encrypt** | `false` | `true` | ✗ Always `false` (Bug 2) |
| **Salt for Feistel cipher** | `"shamir" + id` | `""` (empty) | Always `"shamir" + id` (due to Bug 2) |
| **Passphrase during seed derivation** | Uses user passphrase | Uses user passphrase | Uses user passphrase ✓ |

ERA's implementation creates a unique "dialect" of SLIP39:

- It **decrypts** like neither standard (Bug 1 strips the passphrase)
- It **re-encrypts** like the non-extendable standard only (Bug 2 forces
  `extendable=false`)
- It **derives seeds** correctly using the user's passphrase — but from a
  potentially wrong EMS

This means ERA is only **fully compatible with other ERA wallet instances**
running the same buggy code.  Any standard-compliant implementation (Trezor
or the reference Python library) will produce different results when the
bugs are triggered.

### The "Compatibility Island"

```
                    ┌─────────────────────────────────┐
                    │        ERA Wallet                │
                    │   (custom SLIP39 "dialect")      │
                    │                                  │
                    │  Bug 1: passphrase always ""     │
                    │  Bug 2: extendable always false  │
                    └──────────────┬───────────────────┘
                                   │
                    Only fully compatible with itself
                                   │
              ┌────────────────────┼────────────────────┐
              │                                         │
              ▼                                         ▼
        ┌──────────┐                           ┌──────────────┐
        │  Trezor  │                           │  Reference   │
        │(standard)│                           │   Library    │
        └──────────┘                           └──────────────┘
              │                                         │
              └────────────────────┼────────────────────┘
                                   │
                    Fully compatible with each other
                    (standard SLIP39 implementations)
```

---

## 4. Impact Matrix

### ERA Import Outcomes by Share Type

| Share Type | Passphrase | Default Wallet | Passphrase Wallet | Rework Safe? |
|:-----------|:----------:|:--------------:|:-----------------:|:------------:|
| **Extendable** (current Trezor) | None | ✅ Correct | N/A | ✅ Correct |
| **Extendable** (current Trezor) | Any | ❌ Wrong | ❌ **Wrong** | ❌ **Always wrong** |
| **Non-extendable** (legacy Trezor) | None | ✅ Correct | N/A | ✅ Correct |
| **Non-extendable** (legacy Trezor) | Any | ❌ Wrong | ✅ Correct (*) | ⚠️ Depends (**) |

**(\*)** Saved by the Feistel round-trip property — the salt happens to be
unchanged because Bug 2 is a no-op for non-extendable shares (they're
already `extendable=false`).

**(\*\*)** Rework is correct if the same identifier is preserved; **wallet is
destroyed** if the identifier changes (e.g. to 0 when account session is
lost).

### Why Current Trezor Firmware Is Most Affected

Current Trezor firmware (Safe 3, Safe 5, Safe 7) **forces extendable
backups**.  This means:

- **Bug 1** (passphrase ignored) applies — wrong entropy stored
- **Bug 2** (extendable hardcoded false) applies — salt changes from
  empty to `"shamir" + identifier`
- The Feistel round-trip is **broken** because the salt changed
- **ALL addresses are wrong** — default AND passphrase wallets
- ERA-reworked shares are **permanently wrong** regardless of identifier

For **legacy non-extendable** Trezor shares:

- **Bug 1** applies — wrong entropy stored
- **Bug 2** is a no-op (shares were already non-extendable)
- The Feistel round-trip **preserves the EMS** (same salt)
- Default wallet is wrong, but **passphrase wallet is correct**
- Rework is safe *only if* the identifier is preserved

---

## 5. Confirmed Real-World Scenarios

### Scenario A: Trezor Safe 7 + Passphrase + ERA Import

A user reported:

> "I imported a SLIP39 share from a Trezor Safe 7 and set a passphrase.
> I get different addresses on the ERA wallet compared to the Trezor."

**Root cause:** Trezor Safe 7 forces extendable SLIP39.  ERA Bug 1 +
Bug 2 combine to make **all addresses wrong** — both the default
(no-passphrase) view and the passphrase view show different addresses
than the Trezor.

**Mitigating factor:** The original Trezor shares still work correctly
on the Trezor.  No funds are lost **as long as the original shares are
preserved**.

### Scenario B: Default Works, Passphrase Breaks — But Is Recoverable

A user reported:

> "If I create a SLIP39 share on a Trezor, import it in to the ERA
> wallet, the default address works fine. But if I enable a BIP39
> passphrase, the ERA wallet shows the incorrect address for the
> imported wallet, and any exported shares that are subsequently
> created. [...] if the user only retained the ERA-regenerated shares
> AND used a passphrase, the funds would be unrecoverably lost."

**Update:** Subsequent analysis showed that **recovery IS possible** even
from ERA-mangled shares.  See [Section 10](#10-recovery-getting-your-passphrase-wallet-back) for the full procedure.

**Root cause:** The Trezor creates shares **without a passphrase during
share generation** (passphrase is only applied during seed derivation).
ERA imports the shares and the default wallet matches because Bug 1 is
a no-op when there's no passphrase.  But when the user enables a
passphrase on the Trezor, ERA's Bug 2 means the passphrase-derived
seed is wrong (for extendable shares, the salt is different).

**Apparent path to fund loss (actually recoverable):**

```
Step 1: User creates SLIP39 backup on Trezor (extendable, no passphrase)
Step 2: User imports shares into ERA → default address matches ✓
        (User builds confidence that import is correct)
Step 3: User enables passphrase on Trezor → ERA shows WRONG addresses ✗
Step 4: ERA regenerates/reworks shares → new shares encode WRONG data
Step 5: User discards original Trezor shares, keeps only ERA shares
Step 6: User tries to recover passphrase wallet from ERA shares → WRONG ADDRESSES
Step 7: ✅ RECOVERY: Use recover_from_era_shares() — passphrase wallet IS recoverable
        (ERA preserved the correct default master secret; see Section 10)
```

### Scenario C: Non-Extendable Trezor Seed

A user asked:

> "Does this issue also happen for a non-extendable seed generated on
> a Trezor?"

**Answer: Partially.** For non-extendable shares:

- Bug 1 still applies (passphrase ignored → wrong entropy stored)
- Bug 2 is a **no-op** (shares are already non-extendable)
- The Feistel round-trip **preserves the EMS** (same salt)
- Default wallet: ❌ Wrong (Bug 1 stores wrong entropy)
- Passphrase wallet: ✅ **Correct** (saved by Feistel round-trip)
- ERA rework with same identifier: ✅ Passphrase wallet survives
- ERA rework with different identifier: ❌ Passphrase wallet **destroyed**

This is fundamentally different from extendable shares where
**everything breaks immediately** upon import.

---

## 6. The Feistel Round-Trip Property

The SLIP39 cipher is a **4-round Feistel network** using PBKDF2-HMAC-SHA256.
A key property of Feistel ciphers is:

```
encrypt(decrypt(ciphertext, params), params) = ciphertext
```

When you decrypt a ciphertext and then re-encrypt the result **with the
same parameters** (passphrase, identifier, extendable flag), you get back
the original ciphertext.

### How This Interacts With ERA's Bugs

ERA decrypts with `passphrase=""` (Bug 1) and re-encrypts with
`passphrase=""` (same) but `extendable=false` (Bug 2):

```
Original EMS:     encrypt(MS, user_passphrase, id, extendable_flag)
                              │
ERA decrypts:     decrypt(EMS, "", id, extendable_flag)  →  wrong_entropy
                              │
ERA re-encrypts:  encrypt(wrong_entropy, "", id, false)  →  stored_EMS
```

**For non-extendable shares** (`extendable_flag = false`):
- The decrypt and re-encrypt use the **same salt** (`"shamir" + id`)
- Round-trip holds: `stored_EMS = original EMS`
- Passphrase wallet works because `decrypt(stored_EMS, passphrase)` = `MS`

**For extendable shares** (`extendable_flag = true`):
- Decrypt uses **empty salt** (correct for extendable)
- Re-encrypt uses **`"shamir" + id` salt** (Bug 2 forces non-extendable)
- Salt mismatch breaks round-trip: `stored_EMS ≠ original EMS`
- **Everything is wrong** — passphrase wallet gives wrong seed

This is why extendable shares (current Trezor firmware) are catastrophically
affected while non-extendable shares (legacy Trezor firmware) are only
partially affected.

---

## 7. ERA Share Rework (Backup Regeneration)

ERA wallet offers the ability to regenerate SLIP39 shares from stored account
data.  This "rework" path follows:

```cpp
// CryptoModule::createMnemonic (line 394) → AccountsManager::generateMnemonicSLIP39 (line 102)
// https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L113-L114
generateMnemonics(1, groups, entropy, "", identifier, false, iterationExponent)
//                            ^^^^^^^  ^^              ^^^^^
//                            Bug 1    Bug 1           Bug 2
//                         (wrong for  (always empty)  (always false)
//                         passphrase
//                         shares)
```

### Critical: No Validation or Blocking

ERA has **no code** to prevent rework of passphrase-protected shares:

- [`generateMnemonicSLIP39` (Account.cpp lines 102-127)](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L102-L127) takes entropy and
  identifier as parameters without validation
- There is **no check** for whether the entropy was originally passphrase-protected
- There is **no warning** when reworking potentially corrupted data
- The [`createMnemonic` API (CryptoModule.cpp lines 394-408)](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp#L394-L408) forwards
  parameters without validation

### The Identifier Problem

The identifier for rework comes from `getAccountSlip39Identifier()`:

```cpp
// CryptoModule.cpp line 581-588
// https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp#L581-L588
int CryptoModule::getAccountSlip39Identifier() {
    auto account = _getActiveAccount({});
    if (!account) { return 0; }           // ← Returns 0 if no active session!
    return account->getSlip39Identifier();
}
```

If the active account session is not available, the function returns **0**.
This is a different identifier than the original shares, which breaks the
Feistel round-trip for non-extendable shares:

```
encrypt(wrong_entropy, "", 0, false) ≠ encrypt(wrong_entropy, "", original_id, false)
```

The salt changes (`"shamir" + 0` vs `"shamir" + original_id`), so the reworked
EMS is different from the stored EMS, and the passphrase wallet is permanently
destroyed.

---

## 8. Cross-Device Compatibility

### ERA-Native Shares → Trezor (SAFE)

Shares created entirely within ERA (never imported from another device) are
compatible with Trezor **even with a passphrase**:

- ERA creates shares with `extendable=false` and empty passphrase encryption
- Trezor imports these shares and recovers the same EMS
- Both devices compute the same passphrase-derived wallet
- **Addresses match** ✅

### Trezor → ERA (DANGEROUS — but recoverable)

Current Trezor shares (extendable) imported into ERA with a passphrase:

- ERA silently corrupts the stored data
- Default AND passphrase wallets show **wrong addresses**
- No error, no warning
- **Addresses don't match** ❌
- **However:** The no-passphrase master secret is always correct, and the
  passphrase wallet **can be recovered** using `recover_from_era_shares()`
  — see [Section 10](#10-recovery-getting-your-passphrase-wallet-back)

### ERA-Reworked Shares → New Trezor (CORRUPTED — but recoverable)

When ERA reworks shares that were originally from a Trezor (with passphrase):

- The reworked shares encode ERA's corrupted data
- A new Trezor importing these shares + passphrase produces **wrong
  addresses**
- ERA and the new Trezor **agree with each other** (same wrong data)
  but both **disagree with the original Trezor**
- **However:** For extendable shares, the passphrase wallet is still
  recoverable because the identifier doesn't affect the cipher — see
  [Section 10](#10-recovery-getting-your-passphrase-wallet-back)

### ERA ↔ ERA (COMPATIBLE)

Two ERA wallets exchanging shares will produce the **same results** —
because both run the same buggy code.  However, those results may differ
from what any standard-compliant implementation would produce.

---

## 9. Detailed Code Analysis

### Import Path: `decodeShamirShares()` and `addAccount()`

```
User imports SLIP39 shares into ERA wallet
    │
    ▼
decodeShamirShares(shares, "")     ← Account.cpp line 210
    │                         ^^       https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L210
    │           Passphrase ALWAYS empty (Bug 1)
    │
    ▼
Recover EMS from shares via Shamir's Secret Sharing
    │
    ▼
encryptedMasterSecret.decrypt("")  ← Bug 1: should use user passphrase
    │
    ▼
Store result as "entropy" in AccountSecureData
    │
    ▼
Account constructor:
    EncryptedMasterSecret::fromMasterSecret(entropy, "", id, false, ie)
                                                         ^^^^^
                                                    Bug 2: hardcoded
    │
    ▼
Store re-encrypted EMS for future use
```

### Seed Derivation Path (partially correct)

When the user requests wallet addresses:

```
Read stored EMS from AccountSecureData
    │
    ▼
decrypt(stored_EMS, user_passphrase, ie, id, false)
                    ^^^^^^^^^^^^^^^           ^^^^^
                    User passphrase IS used   But extendable is always false
                    (this part is correct)    (Bug 2 baked into stored EMS)
    │
    ▼
Derived seed (may be wrong if stored EMS is corrupted)
    │
    ▼
BIP32 key derivation → addresses
```

### Rework Path: `createMnemonic()` → `generateMnemonicSLIP39()`

```
User requests share regeneration
    │
    ▼
CryptoModule::createMnemonic()     ← CryptoModule.cpp line 394
    │                                  https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp#L394
    │
    ▼
getAccountSlip39Identifier()       ← May return 0 if no active session!
getAccountSlip39IterationExponent()
    │
    ▼
AccountsManager::generateMnemonicSLIP39(entropy, "", id, false, ie)
    │                                    ^^^^^^^  ^^      ^^^^^
    │                                    Bug 1    Bug 1   Bug 2
    │                               (wrong for PP shares) (hardcoded)
    │
    ▼
generateMnemonics(1, groups, entropy, "", identifier, false, iterationExponent)
    │                                                 ^^^^^
    │                                            Bug 2: hardcoded
    ▼
New SLIP39 shares (may encode wrong data)
```

---

## 10. Recovery: Getting Your Passphrase Wallet Back

ERA's bugs corrupt the passphrase wallet — but the damage is **reversible**.
The no-passphrase (default) master secret is always correct, and that is
enough to reconstruct the original EMS and recover the passphrase wallet.

### Why Recovery Works

ERA's Feistel round-trip preserves the no-passphrase master secret through
its buggy import path:

```
Original EMS on Trezor
    │
    ▼
ERA decrypts with "" (Bug 1):  ms_default = decrypt(EMS, "", ie, id, ext)
    │
    ▼
ERA re-encrypts (Bug 2):       stored_EMS = encrypt(ms_default, "", ie, id, false)
    │
    ▼
ERA presents default wallet:   decrypt(stored_EMS, "", ie, id, false) = ms_default  ✓ CORRECT
```

Since `ms_default` is correct, we can **reverse** the process:

```
ms_default  (correct — from ERA's default wallet)
    │
    ▼
Re-encrypt with ORIGINAL parameters:  recovered_EMS = encrypt(ms_default, "", ie, id, ext)
    │
    ▼
Decrypt with passphrase:               ms_passphrase = decrypt(recovered_EMS, pp, ie, id, ext)
    │
    ▼
RECOVERED passphrase wallet  ✓
```

### The Key Insight: Extendable Shares Don't Need the Identifier

The SLIP39 Feistel cipher uses a **salt** derived from the identifier and
extendable flag:

```python
def _get_salt(identifier, extendable):
    if extendable:
        return bytes()                      # ← Empty! Identifier not used!
    return "shamir" + identifier.to_bytes(2, "big")  # ← Identifier IS used
```

**For extendable shares** (all current Trezor Safe 7 firmware): the salt is
always empty.  The identifier has **no effect** on the cipher.  This means:

- `encrypt(ms, pp, ie, ANY_ID, True)` gives the **same result** for any identifier
- Recovery needs only: `ms_default` + `passphrase` + `iteration_exponent`
- **No brute-forcing needed.  No identifier guessing.  Just math.**

**Important:** ERA may also change the **iteration exponent** during import
(e.g. from 1 to 0).  The recovery must use the **original** iteration
exponent from the Trezor shares, not the value stored in ERA's re-generated
shares.  If you still have the original Trezor share, the iteration exponent
can be read from its metadata.

**For non-extendable shares** (legacy Trezor firmware): the identifier is part
of the salt.  However, ERA's passphrase wallet is already correct for
non-extendable shares (Bug 2 is a no-op), so recovery is only needed if ERA
reworked the shares with a changed identifier.  Even then, the 15-bit
identifier space (0–32767) can be brute-forced (a few minutes with
`--brute-force-identifier`).

### Recovery Matrix

| Scenario | Recovery needed? | Identifier needed? | How |
|----------|------------------|--------------------|-----|
| **Extendable**, ERA-imported | YES | NO | `ms_default + pp + ie` |
| **Extendable**, ERA-reworked, same id | YES | NO | `ms_default + pp + ie` |
| **Extendable**, ERA-reworked, changed id | YES | **NO** (id irrelevant) | `ms_default + pp + ie` |
| **Non-extendable**, ERA-imported | Not needed (already correct) | — | — |
| **Non-extendable**, ERA-reworked, same id | Not needed (already correct) | — | — |
| **Non-extendable**, ERA-reworked, changed id | YES | YES (brute-force 32768) | `ms_default + pp + ie + id` |

### Step-by-Step Recovery Procedure

For a user who imported Trezor Safe 7 (extendable) shares into ERA with a
passphrase and now has wrong addresses:

1. **Get the default master secret** from ERA by combining shares with empty
   passphrase: `ms_default = combine_mnemonics(era_shares, b"")`

2. **Get the original iteration exponent** from the original Trezor share
   metadata.  ERA may change this value during import (e.g. from 1 to 0).

3. **Reconstruct the original EMS:**
   `original_ems = encrypt(ms_default, b"", original_ie, 0, True)`
   (The identifier value doesn't matter — any value works for extendable.)

4. **Decrypt with your passphrase:**
   `ms_passphrase = decrypt(original_ems, your_passphrase, original_ie, 0, True)`

5. **Use `ms_passphrase`** as the BIP32 seed to derive your correct addresses.

The `recover_from_era_shares()` function in this library automates this
process.

### CLI Recovery Tool

The library includes a CLI command that automates the recovery interactively.
Install with `pip install shamir-mnemonic[cli]`, then run:

```console
$ shamir recover-era --passphrase TREZOR --iteration-exponent 1
```

Options:

- `--passphrase` / `-p` — your original Trezor passphrase (**required**)
- `--iteration-exponent` / `-E` — original iteration exponent from the Trezor
  shares (if ERA changed it during import; read from original share metadata)
- `--extendable` / `--no-extendable` — original share type (default: extendable)
- `--original-identifier` / `-I` — override identifier (only for non-extendable
  ERA-reworked shares where the identifier changed)
- `--brute-force-identifier` / `-B` — try all 32768 identifiers (for
  non-extendable shares where the original identifier is unknown)
- `--verify-secret` — expected passphrase master secret in hex (required
  with `--brute-force-identifier` to know when the correct identifier is found)

To run from a local checkout without installing:

```console
$ python3 -m shamir_mnemonic.cli recover-era -p TREZOR -E 1
```

### Real-World Recovery Example

Original Trezor Safe 7 share (1-of-1, extendable, iteration_exponent=1):

    center industry academic academic demand squeeze reaction detect
    snapshot inside surface rhythm owner revenue careful beam fake
    brother rocky froth

- Default master secret: `19b66f8284a53453c7ae9f1b781499ee` ✓
- With passphrase "test": `b2c7ff3a404de4a18853cc5d77031f97` ✓

After import into ERA, the wallet produced mangled shares (2-of-2,
non-extendable, iteration_exponent=0):

    mason walnut academic agency civil scholar liberty funding edge
    capture kidney academic dominant fragment pickup ancestor grin
    beam welcome scramble

    mason walnut academic acid category clinic sidewalk syndrome plot
    view obesity sled drink aunt gesture flash decent pajamas sharp step

- Default master secret: `19b66f8284a53453c7ae9f1b781499ee` ✓ (correct)
- With passphrase "test": `3a0fb8e642cbbe0b48949ccf043d341f` ✗ (WRONG)

ERA changed both `extendable` (True→False) and `iteration_exponent` (1→0).
Recovery:

```console
$ shamir recover-era --passphrase test --iteration-exponent 1
Enter your ERA-mangled SLIP39 shares (enough to meet the threshold).
When done, the tool will recover your passphrase wallet.

Enter a recovery share: mason walnut academic agency civil scholar liberty
  funding edge capture kidney academic dominant fragment pickup ancestor
  grin beam welcome scramble
Enter a recovery share: mason walnut academic acid category clinic sidewalk
  syndrome plot view obesity sled drink aunt gesture flash decent pajamas
  sharp step

Recovering passphrase wallet...
SUCCESS!
Default master secret (no passphrase): 19b66f8284a53453c7ae9f1b781499ee
Recovered passphrase master secret:     b2c7ff3a404de4a18853cc5d77031f97
```

### Non-Extendable Recovery

For **non-extendable** shares (legacy Trezor firmware), recovery is only
needed if ERA **reworked** the shares with a different identifier.  If ERA
only imported them (without reworking), the passphrase wallet is already
correct.

When recovery IS needed (ERA reworked with a new identifier), you need the
**original identifier**.  There are two ways to get it:

**Option A: Read from original Trezor shares** (if you still have them)

Use `--no-extendable` and `--original-identifier`:

```console
$ shamir recover-era --passphrase TREZOR --no-extendable --original-identifier 12345
```

**Option B: Brute-force** (if original shares are lost)

The identifier is only 15 bits (0–32767).  Use `--brute-force-identifier`
with `--verify-secret` (the expected passphrase master secret in hex):

```console
$ shamir recover-era --passphrase TREZOR --no-extendable \
    --brute-force-identifier --verify-secret <expected_ms_hex>
```

The brute-force tries all 32768 possible identifiers.  This takes a few
minutes for iteration_exponent=0, longer for higher values.

---

## 11. Recommendations

### For ERA Wallet Users

1. **Do NOT import Trezor SLIP39 shares into ERA if you use a passphrase.**
   The addresses will be wrong for current (extendable) Trezor shares.

2. **Do NOT discard original Trezor shares** after importing into ERA.
   The original shares are the safest way to recover the correct wallet.

3. **Do NOT rely on ERA-reworked shares** as your only backup if the
   original shares came from a Trezor with a passphrase.

4. **If you already imported and have wrong addresses:** Your passphrase
   wallet **can be recovered** — see [Section 10](#10-recovery-getting-your-passphrase-wallet-back).
   For current Trezor (extendable) shares, you need your ERA shares,
   your passphrase, and the original iteration exponent from the Trezor
   share (if ERA changed it).  Use
   `shamir recover-era -p YOUR_PASSPHRASE -E ORIGINAL_IE` from the CLI,
   or `recover_from_era_shares()` from Python.

5. **If you still have original Trezor shares:** They work correctly on a
   Trezor.  You can also use them directly with the reference library.

### For ERA Wallet Developers

1. **Bug 1 fix:** Pass the user's passphrase to `encryptedMasterSecret.decrypt()`
   in both `decodeShamirShares()` and `addAccount()`.

2. **Bug 2 fix:** Preserve the original `extendable` flag from the imported
   shares, and use it when re-encrypting for storage.

3. **Identifier safety:** Validate that `getAccountSlip39Identifier()` returns
   the correct identifier before rework.  Never silently use `0`.

4. **Add validation:** Before rework, verify that the stored entropy matches
   what a round-trip would produce.  Warn the user if it doesn't.

5. **Add warnings:** When importing passphrase-protected shares, prompt the
   user for the passphrase and validate the result before storing.

### For Users of Other Wallets

Standard-compliant SLIP39 implementations (Trezor, the reference Python
library, etc.) are **not affected** by these bugs.  The bugs are specific
to the ERA wallet's import and re-encryption code paths.

---

## Appendix A: Reproduction

All findings in this report are reproduced by automated tests in
[`test_shamir.py`](https://github.com/3rdIteration/python-shamir-mnemonic/blob/master/test_shamir.py).
Key tests:

| Test | What It Proves |
|------|----------------|
| `test_era_import_extendable_with_passphrase` | Bug 2 breaks Feistel round-trip for extendable shares |
| `test_era_import_nonextendable_with_passphrase_correct_passphrase_wallet` | Bug 2 is no-op for non-extendable; passphrase wallet survives |
| `test_era_no_block_scenario_2_passphrase_ignored_during_import` | ERA has no code to block passphrase-ignored import |
| `test_era_no_block_scenario_4_rework_with_new_identifier` | ERA has no code to block destructive rework |
| `test_era_silently_accepts_all_trezor_share_types` | ERA never rejects any import |
| `test_era_import_acceptance_vs_correctness_matrix` | Complete compatibility matrix |
| `test_trezor_safe_7_with_passphrase_era_gives_different_addresses` | Confirmed real-world Safe 7 scenario |
| `test_confirmed_fault_default_works_but_passphrase_breaks_and_funds_lost` | Confirmed fault scenario (passphrase breaks; recoverable via Section 10) |
| `test_trezor_nonextendable_seed_imported_to_era_with_passphrase` | Non-extendable shares: partial safety |
| `test_era_native_shares_imported_to_trezor_with_passphrase_is_safe` | ERA→Trezor direction: safe for native shares |
| `test_era_reworked_shares_imported_to_trezor_with_passphrase_both_wrong` | ERA→Trezor direction: corrupted for reworked shares |
| `test_upstream_vectors_would_have_caught_era_bugs` | Upstream vectors.json catches both bugs |
| `test_extendable_salt_is_empty_so_identifier_is_irrelevant` | Extendable cipher ignores identifier |
| `test_recovery_extendable_ms_default_is_enough` | Recovery: ms_default + passphrase is sufficient |
| `test_recovery_extendable_reworked_changed_id` | Recovery works even when identifier changed |
| `test_recovery_summary_matrix` | Complete recovery matrix for all scenarios |

The simulation functions `simulate_era_import()`, `simulate_era_rework()`,
and `recover_from_era_shares()`
in [`shamir_mnemonic/shamir.py`](https://github.com/3rdIteration/python-shamir-mnemonic/blob/master/shamir_mnemonic/shamir.py)
model ERA's exact code paths, with inline references to the ERA C++ source
([`Account.cpp`](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp), [`CryptoModule.cpp`](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp)).

## Appendix B: Standard SLIP39 References

- **SLIP-0039 specification:** https://github.com/satoshilabs/slips/blob/master/slip-0039.md
- **Reference implementation:** https://github.com/trezor/python-shamir-mnemonic
- **Trezor firmware SLIP39:** https://github.com/trezor/trezor-firmware (`core/src/trezor/crypto/slip39.py`)

## Appendix C: ERA Wallet Source References

All ERA code references in this report point to the [`ERA-crypto-p` repository](https://github.com/ERAWLT/ERA-crypto-p/tree/1504ed05ae4cc90128e679f48afc2a6de6fb963a)
under [github.com/ERAWLT](https://github.com/ERAWLT) at commit `1504ed0`:

| File | Lines | Link | Bug |
|------|-------|------|-----|
| `Account.cpp` | 210 | [permalink](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L210) | Bug 1: `decodeShamirShares()` uses empty passphrase |
| `Account.cpp` | 433 | [permalink](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L433) | Bug 1: `addAccount()` uses empty passphrase |
| `Account.cpp` | 850-851 | [permalink](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L850-L851) | Bug 2: Account constructor hardcodes `extendable=false` |
| `Account.cpp` | 102-127 | [permalink](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/wallet/Account.cpp#L102-L127) | Rework: `generateMnemonicSLIP39()` uses wrong entropy |
| `CryptoModule.cpp` | 394-408 | [permalink](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp#L394-L408) | Rework: `createMnemonic()` forwards without validation |
| `CryptoModule.cpp` | 581-588 | [permalink](https://github.com/ERAWLT/ERA-crypto-p/blob/1504ed05ae4cc90128e679f48afc2a6de6fb963a/src/CryptoModule.cpp#L581-L588) | Identifier: `getAccountSlip39Identifier()` returns 0 on error |

## Appendix D: Upstream Test Vectors Would Have Caught Both Bugs

The upstream reference library
([trezor/python-shamir-mnemonic](https://github.com/trezor/python-shamir-mnemonic))
ships with **`vectors.json`** — a set of 45 test vectors (15 valid, 30
invalid/error cases) that existed **before any changes in this PR**.  These
vectors are sufficient to detect **both** ERA bugs.

### Bug 1: All Valid Vectors Use Passphrase `"TREZOR"`

Every valid test vector in `vectors.json` is designed to be recovered with
passphrase `b"TREZOR"` (as shown in the upstream `test_vectors()` function).
ERA's Bug 1 — always passing an empty string `""` to `decrypt()` — causes
**every single valid vector** (15 of 15) to produce a wrong master secret.

An implementation that passes `""` instead of `"TREZOR"` would fail all 15
valid vectors immediately.

### Bug 2: Extendable Vectors Exist (Vectors 41-44)

Vectors 41-44 are extendable shares with `extendable=True` encoded in their
share metadata.  ERA's Bug 2 — hardcoding `extendable=false` — changes the
Feistel cipher salt from `""` (empty, as specified for extendable) to
`"shamir" + identifier_bytes` (the non-extendable salt).  This produces a
**completely different master secret** even if the passphrase were correct.

### Combined Effect

For the 4 extendable vectors, both bugs apply simultaneously:

| Bug Applied | Passphrase | Extendable | Salt | Result |
|------------|------------|------------|------|--------|
| None (correct) | `"TREZOR"` | `true` | `""` | ✓ Correct secret |
| Bug 1 only | `""` | `true` | `""` | ✗ Wrong secret |
| Bug 2 only | `"TREZOR"` | `false` | `"shamir"+id` | ✗ Wrong secret |
| Both bugs | `""` | `false` | `"shamir"+id` | ✗ Wrong secret (different from above) |

All three wrong results are **different values** — each bug independently
corrupts the output, and combined they produce a third distinct wrong value.

### Conclusion

If ERA had run their SLIP39 implementation against the upstream
`vectors.json` test suite — which was freely available from the reference
library — **both bugs would have been caught immediately**.  The test
`test_upstream_vectors_would_have_caught_era_bugs()` in this repository
explicitly demonstrates this.
