# PSBT 2-of-3 Multisig Signing Guide

This document describes how to use BIP-174 PSBTs to coordinate a **2-of-3 P2SH multisig** spend across two independent signers. This is one of the most common real-world PSBT use cases: a transaction that requires two out of three keyholders to approve before it can be broadcast.

We simulate the workflow using three scripts (in `examples/`) that each execute one or more BIP-174 roles. Both signing scripts run on the same machine but use different private keys, just as they would if two keyholders were signing on separate devices or in separate locations.

```bash
python examples/psbt_2of3_create.py    # Step 1: Create unsigned PSBT
python examples/psbt_2of3_sign1.py     # Step 2: Signer 1 adds partial signature
python examples/psbt_2of3_sign2.py     # Step 3: Signer 2 signs, combines, finalizes, extracts
```

## Background

### What is 2-of-3 multisig?

A 2-of-3 multisig address is controlled by three public keys, and any two of the three corresponding private keys are required to spend funds from it. The locking script (redeemScript) looks like:

```
OP_2 <pubkey_1> <pubkey_2> <pubkey_3> OP_3 OP_CHECKMULTISIG
```

The address itself is the hash of this redeemScript, wrapped in P2SH format (`3...` on mainnet, `2...` on testnet).

### Why PSBT?

Without PSBT, coordinating multiple signers requires passing around raw transaction bytes and manually managing partial signatures. PSBT solves this by defining a standard container that carries:

- The unsigned transaction
- UTXO data needed for signing
- Script metadata (redeemScript, witnessScript)
- Partial signatures from each signer

Each participant adds their piece and passes the PSBT along. No signer needs to understand what the others are doing; they just sign and pass it on.

### BIP-174 roles in this workflow

BIP-174 defines six roles. In our 2-of-3 scenario, they map to three scripts:

| Role | Responsibility | Script |
|---|---|---|
| **Creator** | Builds the unsigned transaction and wraps it in a PSBT | `psbt_2of3_create.py` |
| **Updater** | Adds the UTXO info, redeemScript, and sighash type | `psbt_2of3_create.py` |
| **Signer 1** | Adds a partial signature using private key A | `psbt_2of3_sign1.py` |
| **Signer 2** | Adds a partial signature using private key B | `psbt_2of3_sign2.py` |
| **Combiner** | Merges the two signed PSBTs into one | `psbt_2of3_sign2.py` |
| **Finalizer** | Constructs the final scriptSig from partial signatures | `psbt_2of3_sign2.py` |
| **Extractor** | Pulls out the fully signed transaction for broadcast | `psbt_2of3_sign2.py` |

Note: the Creator and Updater roles are combined in the first script, and the Combiner/Finalizer/Extractor are combined in the second signer's script. This is a common pattern — in practice the last signer usually finalizes and extracts.

## Setup

### Shared knowledge (all participants know this)

Before the workflow starts, all three keyholders have agreed on:

1. **The three public keys** that form the multisig (and their order in the redeemScript).
2. **The redeemScript** itself, derived from those three public keys.
3. **The P2SH address** derived from the redeemScript — this is where funds are locked.

### Private key distribution

- **Key A** — held by Signer 1 only
- **Key B** — held by Signer 2 only
- **Key C** — held by a third party (cold storage, escrow, etc.) — not used in this spend

Any two of the three can sign. In this example, Signers 1 and 2 cooperate.

## Workflow

The PSBT flows through the scripts as a **base64-encoded string**. In production this string would be passed via file, QR code, NFC, or a coordination server. Here we write it to `.psbt` files on disk.

```
              psbt_2of3_create.py
              (Creator + Updater)
                    |
                    v
              unsigned.psbt          <-- base64 PSBT with UTXO + redeemScript
                    |
         +----------+----------+
         |                     |
         v                     v
  psbt_2of3_sign1.py   (copy of unsigned.psbt)
  (Signer 1)                   |
         |                     |
         v                     |
  signer1.psbt                 |
  (has sig from Key A)         |
         |                     |
         +----------+----------+
                    |
                    v
            psbt_2of3_sign2.py
            (Signer 2 + Combiner +
             Finalizer + Extractor)
                    |
                    v
             final_tx.hex          <-- raw signed transaction, ready to broadcast
```

### Step 1: Create the PSBT (`psbt_2of3_create.py`)

This script acts as both **Creator** and **Updater**.

**Creator responsibilities:**
- Build a `Transaction` with the desired inputs (UTXOs locked in the multisig address) and outputs (where the funds are going).
- Wrap it in a `PSBT` object. The constructor automatically strips scriptSigs and segwit data, producing a clean unsigned transaction.

**Updater responsibilities:**
- Attach the **non-witness UTXO** (the full previous transaction) for each input. This lets signers verify the amount being spent.
- Attach the **redeemScript** for each input. Without it, signers cannot determine what they are signing for.

```python
# Pseudocode for psbt_2of3_create.py

setup("testnet")

# 1. Define the 3 public keys and build the redeemScript
pk1 = PublicKey(...)
pk2 = PublicKey(...)
pk3 = PublicKey(...)

redeem_script = Script([
    "OP_2",
    pk1.to_hex(), pk2.to_hex(), pk3.to_hex(),
    "OP_3", "OP_CHECKMULTISIG"
])

# 2. Create the unsigned transaction (Creator)
txin = TxInput(prev_txid, vout_index)
txout = TxOutput(amount, destination_script_pubkey)
tx = Transaction([txin], [txout])

# 3. Wrap in PSBT
psbt = PSBT(tx)

# 4. Update with UTXO and redeemScript (Updater)
psbt.update_input(0,
    non_witness_utxo=prev_tx,       # full previous transaction
    redeem_script=redeem_script      # so signers know the multisig structure
)

# 5. Export
with open("unsigned.psbt", "w") as f:
    f.write(psbt.to_base64())
```

**What the PSBT contains at this point:**
- Global: the unsigned transaction
- Input 0: `non_witness_utxo` (full prev tx) + `redeem_script` (the 2-of-3 script)
- Input 0: no signatures yet

### Step 2: Signer 1 signs (`psbt_2of3_sign1.py`)

This script acts as **Signer 1** only.

**Signer responsibilities (per BIP-174):**
- Parse the PSBT.
- Verify the UTXO data is consistent (txid of `non_witness_utxo` matches the input's referenced txid).
- Produce a partial signature using their private key.
- Add the signature to the PSBT as a `partial_sig` entry.
- Export the updated PSBT.

```python
# Pseudocode for psbt_2of3_sign1.py

setup("testnet")

# 1. Load the unsigned PSBT
with open("unsigned.psbt") as f:
    psbt = PSBT.from_base64(f.read().strip())

# 2. Load Signer 1's private key
sk1 = PrivateKey("cXXXX...")  # Key A (WIF format)

# 3. Sign input 0
psbt.sign_input(0, sk1)

# 4. Export — DO NOT finalize (need Signer 2's signature too)
with open("signer1.psbt", "w") as f:
    f.write(psbt.to_base64())
```

**What the PSBT contains at this point:**
- Everything from before, plus:
- Input 0: `partial_sigs` now has one entry: `{pubkey_A: signature_A}`

**Important:** Signer 1 must NOT finalize the PSBT. Finalization locks in the scriptSig and clears partial signatures. Since we need a second signature, the PSBT must remain in its partially-signed state.

### Step 3: Signer 2 signs, combines, finalizes, and extracts (`psbt_2of3_sign2.py`)

This script acts as **Signer 2**, **Combiner**, **Finalizer**, and **Extractor**.

```python
# Pseudocode for psbt_2of3_sign2.py

setup("testnet")

# 1. Load both PSBTs
with open("unsigned.psbt") as f:
    psbt_unsigned = PSBT.from_base64(f.read().strip())

with open("signer1.psbt") as f:
    psbt_signed1 = PSBT.from_base64(f.read().strip())

# 2. Sign the unsigned copy with Signer 2's key (Signer)
sk2 = PrivateKey("cYYYY...")  # Key B (WIF format)
psbt_unsigned.sign_input(0, sk2)
# psbt_unsigned now has: partial_sigs = {pubkey_B: signature_B}

# 3. Combine the two PSBTs (Combiner)
combined = psbt_signed1.combine(psbt_unsigned)
# combined now has: partial_sigs = {pubkey_A: sig_A, pubkey_B: sig_B}

# 4. Finalize (Finalizer)
combined.finalize()
# This constructs the final scriptSig:
#   OP_0 <sig_A> <sig_B> <redeemScript>
# and clears partial_sigs, redeem_script, etc.

# 5. Extract the signed transaction (Extractor)
final_tx = combined.extract_transaction()
tx_hex = final_tx.serialize()

with open("final_tx.hex", "w") as f:
    f.write(tx_hex)

print(f"Transaction ready to broadcast: {tx_hex}")
```

**What happens during finalization:**

The `finalize()` method detects that the input is a P2SH multisig (by inspecting the redeemScript). It:
1. Collects the partial signatures from `partial_sigs`.
2. Orders them to match the pubkey order in the redeemScript (Bitcoin's `OP_CHECKMULTISIG` requires this).
3. Builds the scriptSig: `OP_0 <sig_1> <sig_2> <serialized_redeemScript>`.
4. Clears all non-final fields (`partial_sigs`, `redeem_script`, `bip32_derivs`, `sighash_type`).

The `extract_transaction()` method takes the finalized scriptSig and places it into a standard Bitcoin transaction that can be serialized and broadcast.

## Alternative flow: sequential signing

Instead of combining two separately-signed PSBTs, Signer 2 can sign the PSBT that Signer 1 already signed:

```
unsigned.psbt  -->  Signer 1 signs  -->  signer1.psbt  -->  Signer 2 signs  -->  finalize + extract
```

In this flow, Signer 2's script is simpler:

```python
# Load Signer 1's output directly
with open("signer1.psbt") as f:
    psbt = PSBT.from_base64(f.read().strip())

# Sign on top of it (adds a second partial_sig)
sk2 = PrivateKey("cYYYY...")
psbt.sign_input(0, sk2)
# psbt now has: partial_sigs = {pubkey_A: sig_A, pubkey_B: sig_B}

# Finalize and extract (no combine needed)
psbt.finalize()
final_tx = psbt.extract_transaction()
```

This is simpler but requires Signer 2 to wait for Signer 1. The combine-based flow allows both signers to work in parallel.

## File summary

| File | BIP-174 Roles | Input | Output |
|---|---|---|---|
| `psbt_2of3_create.py` | Creator + Updater | UTXO details, 3 public keys | `unsigned.psbt` |
| `psbt_2of3_sign1.py` | Signer | `unsigned.psbt`, Key A | `signer1.psbt` |
| `psbt_2of3_sign2.py` | Signer + Combiner + Finalizer + Extractor | `unsigned.psbt`, `signer1.psbt`, Key B | `final_tx.hex` |

## Key points

- **Never finalize early.** Only finalize after all required signatures (2 of 3) are present. Finalizing with fewer signatures produces an invalid transaction.
- **Public key order matters.** `OP_CHECKMULTISIG` expects signatures in the same order as the public keys in the redeemScript. The PSBT finalizer handles this automatically by matching pubkeys from `partial_sigs` against the redeemScript.
- **The PSBT is not confidential.** Anyone who sees the PSBT can see the transaction details and public keys. However, they cannot forge signatures without the private keys.
- **The redeemScript must be attached.** Without it in the PSBT, signers cannot determine what type of script they are signing for, and the finalizer cannot construct the correct scriptSig.
- **UTXO data is mandatory.** The `non_witness_utxo` (full previous transaction) lets each signer independently verify the amount being spent, preventing fee-manipulation attacks.

## Extending to P2SH-P2WSH (segwit multisig)

For a segwit-wrapped multisig (P2SH-P2WSH), the flow is identical except:

1. The `update_input` call also includes a `witness_script` (the raw multisig script) and a `witness_utxo` (the specific output being spent).
2. The `redeem_script` becomes `OP_0 <SHA256(witness_script)>` — a P2WSH wrapper.
3. Finalization produces both a scriptSig (pushing the redeemScript) and a witness stack (`OP_0 <sig_1> <sig_2> <witness_script>`).

The PSBT library handles these differences transparently. The signing scripts are nearly identical; only the `update_input` call changes.
