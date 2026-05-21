# SPHINCS+ / SLH-DSA Concise Technical Reference

Based on: NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)

---

# 1. Core Concepts

SLH-DSA (SPHINCS+) is composed of:

* **WOTS+** — one-time signature scheme
* **XMSS** — Merkle-tree based multi-time signature scheme
* **Hypertree** — layered XMSS trees
* **FORS** — few-time signature scheme

The overall signature flow:

```text
Message
  ↓
Randomized hashing (R || digest)
  ↓
FORS signs digest fragment
  ↓
XMSS hypertree authenticates FORS public key
  ↓
Final SLH-DSA signature
```

---

# 2. Domain Separation

Domain separation is implemented primarily through:

* `PK.seed`
* `ADRS` (32-byte address structure)
* Address `type` fields
* Distinct hash invocations

Every hash/PRF call uses a unique address context.

---

# 3. Core Cryptographic Functions

## 3.1 PRFmsg

```text
PRFmsg(SK.prf, opt_rand, M) -> n bytes
```

Generates randomized message nonce `R`.

Used for:

* Signature randomization
* Side-channel resistance
* Multi-target protection

---

## 3.2 Hmsg

```text
Hmsg(R, PK.seed, PK.root, M) -> digest
```

Produces digest used for:

* FORS message digest
* Tree indices
* Leaf indices

---

## 3.3 PRF

```text
PRF(PK.seed, SK.seed, ADRS) -> n bytes
```

Generates secret values for:

* WOTS+ chains
* FORS leaves

---

## 3.4 F

```text
F(PK.seed, ADRS, M1) -> n bytes
```

Single-input compression hash.

Used in:

* WOTS+ chains
* FORS leaf hashing

---

## 3.5 H

```text
H(PK.seed, ADRS, M2) -> n bytes
```

Two-input compression hash.

Used in:

* XMSS internal nodes
* FORS tree nodes

---

## 3.6 T_l

```text
T_l(PK.seed, ADRS, Ml) -> n bytes
```

Compresses multiple `n`-byte strings into one.

Used for:

* WOTS+ public key compression
* FORS root compression

---

# 4. ADRS (Addressing System)

## 4.1 ADRS Layout

All hash operations are domain-separated using a 32-byte address.

```text
+-------------------+
| layer address     | 4 bytes
+-------------------+
| tree address      | 12 bytes
+-------------------+
| type              | 4 bytes
+-------------------+
| type-specific     | 12 bytes
+-------------------+
```

---

# 5. ADRS Types

## 5.1 WOTS_HASH (type = 0)

Used during WOTS+ chain hashing.

```text
layer address
tree address
type = WOTS_HASH
key pair address
chain address
hash address
```

---

## 5.2 WOTS_PK (type = 1)

Used when compressing WOTS+ public keys.

```text
layer address
tree address
type = WOTS_PK
key pair address
padding = 0
```

---

## 5.3 TREE (type = 2)

Used for XMSS tree hashing.

```text
layer address
tree address
type = TREE
padding = 0
tree height
tree index
```

---

## 5.4 FORS_TREE (type = 3)

Used for FORS Merkle nodes.

```text
layer address = 0
tree address
type = FORS_TREE
key pair address
tree height
tree index
```

---

## 5.5 FORS_ROOTS (type = 4)

Used when compressing FORS roots.

```text
layer address = 0
tree address
type = FORS_ROOTS
key pair address
padding = 0
```

---

## 5.6 WOTS_PRF (type = 5)

Used when generating WOTS+ secret values.

```text
layer address
tree address
type = WOTS_PRF
key pair address
chain address
hash address = 0
```

---

## 5.7 FORS_PRF (type = 6)

Used when generating FORS secret values.

```text
layer address = 0
tree address
type = FORS_PRF
key pair address
tree height = 0
tree index
```

---

# 6. ADRS Member Functions

## Setters

```text
ADRS.setLayerAddress(l)
ADRS.setTreeAddress(t)
ADRS.setTypeAndClear(Y)
ADRS.setKeyPairAddress(i)
ADRS.setChainAddress(i)
ADRS.setTreeHeight(i)
ADRS.setHashAddress(i)
ADRS.setTreeIndex(i)
```

## Getters

```text
ADRS.getKeyPairAddress()
ADRS.getTreeIndex()
```

---

# 7. Integer / Byte Conversion

## toInt

```text
toInt(X, n)
```

Converts:

```text
n-byte big-endian string -> integer
```

Pseudocode:

```text
total <- 0
for i in [0..n-1]:
    total <- 256 * total + X[i]
return total
```

---

## toByte

```text
toByte(x, n)
```

Converts:

```text
integer -> n-byte big-endian string
```

Core logic:

```text
for i in [0..n-1]:
    S[n-1-i] <- x mod 256
    x <- floor(x / 256)
```

---

# 8. WOTS+

## 8.1 Chain Function

```text
chain(X, i, s, PK.seed, ADRS)
```

Applies repeated hashing:

```text
F(PK.seed, ADRS, X)
```

for `s` iterations.

---

## 8.2 WOTS+ Public Key Generation

```text
wots_pkGen(SK.seed, PK.seed, ADRS)
```

Flow:

```text
for each chain:
    sk <- PRF(...)
    pk_elem <- chain(sk, 0, w-1)

compress all chains with T_l
```

---

## 8.3 WOTS+ Signing

```text
wots_sign(M, SK.seed, PK.seed, ADRS)
```

Flow:

```text
base_w <- base_2b(M)
checksum <- computed checksum

for each chain:
    sig[i] <- chain(sk[i], 0, msg_digit[i])
```

---

## 8.4 WOTS+ Public Key Recovery

```text
wots_pkFromSig(sig, M, PK.seed, ADRS)
```

Flow:

```text
for each chain:
    pk[i] <- chain(sig[i], msg_digit[i], w-1-msg_digit[i])

compress using T_l
```

---

# 9. XMSS

## 9.1 XMSS Node Generation

```text
xmss_node(SK.seed, i, z, PK.seed, ADRS)
```

Recursive Merkle node construction.

Leaf case:

```text
Generate WOTS+ public key
Compress with T_l
```

Internal node:

```text
left  <- xmss_node(...)
right <- xmss_node(...)
node  <- H(left || right)
```

---

## 9.2 XMSS Signing

```text
xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
```

Produces:

* WOTS+ signature
* Authentication path

---

## 9.3 XMSS Public Key Recovery

```text
xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)
```

Flow:

```text
recover WOTS+ pk
rebuild Merkle root using auth path
```

---

# 10. Hypertree

## 10.1 Hypertree Signing

```text
ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
```

Process:

```text
Layer 0 XMSS signs FORS root
Layer 1 XMSS signs Layer 0 root
...
Top layer signs previous layer root
```

---

## 10.2 Hypertree Verification

```text
ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
```

Process:

```text
reconstruct each XMSS root upward
compare final root with PK.root
```

---

# 11. FORS

## 11.1 FORS Secret Key Generation

```text
fors_skGen(SK.seed, PK.seed, ADRS, idx)
```

Uses:

```text
PRF(PK.seed, SK.seed, ADRS)
```

---

## 11.2 FORS Node Generation

```text
fors_node(SK.seed, i, z, PK.seed, ADRS)
```

Leaf:

```text
sk <- PRF(...)
leaf <- F(sk)
```

Internal:

```text
node <- H(left || right)
```

---

## 11.3 FORS Signing

```text
fors_sign(md, SK.seed, PK.seed, ADRS)
```

For each selected tree:

```text
reveal secret leaf
include authentication path
```

---

## 11.4 FORS Public Key Recovery

```text
fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)
```

Flow:

```text
rebuild each FORS root
compress all roots using T_l
```

---

# 12. Internal SLH-DSA Functions

---

## 12.1 Internal Key Generation

```text
slh_keygen_internal(SK.seed, SK.prf, PK.seed)
```

Flow:

```text
Generate top XMSS root
PK.root <- top root

SK = {
    SK.seed,
    SK.prf,
    PK.seed,
    PK.root
}

PK = {
    PK.seed,
    PK.root
}
```

---

## 12.2 Internal Signing

```text
slh_sign_internal(M, SK, addrnd)
```

Flow:

```text
R <- PRFmsg(SK.prf, addrnd, M)
digest <- Hmsg(R, PK.seed, PK.root, M)

Split digest into:
    md
    idx_tree
    idx_leaf

SIG_FORS <- fors_sign(md)
PK_FORS  <- fors_pkFromSig(SIG_FORS)

SIG_HT <- ht_sign(PK_FORS)

SIG = (R, SIG_FORS, SIG_HT)
```

---

## 12.3 Internal Verification

```text
slh_verify_internal(M, SIG, PK)
```

Flow:

```text
Extract:
    R
    SIG_FORS
    SIG_HT

Compute digest:
    digest <- Hmsg(...)

Recover:
    PK_FORS <- fors_pkFromSig(...)

Verify hypertree:
    root <- ht_verify(...)

Accept iff:
    root == PK.root
```

---

# 13. External SLH-DSA Functions

---

## 13.1 Key Generation

```text
slh_keygen()
```

Flow:

```text
Generate random:
    SK.seed
    SK.prf
    PK.seed

Return:
    slh_keygen_internal(...)
```

---

## 13.2 Pure SLH-DSA Signing

```text
slh_sign(M, ctx, SK)
```

Domain-separated message:

```text
M' = prefix || ctx || M
```

Then:

```text
slh_sign_internal(M', SK, opt_rand)
```

---

## 13.3 HashSLH-DSA Signing

```text
hash_slh_sign(M, ctx, PH, SK)
```

Flow:

```text
PHM <- PreHash(M)
M'  <- prefix || ctx || PHM

slh_sign_internal(M')
```

---

## 13.4 Pure SLH-DSA Verification

```text
slh_verify(M, SIG, ctx, PK)
```

Flow:

```text
Rebuild M'
Call slh_verify_internal(M')
```

---

## 13.5 HashSLH-DSA Verification

```text
hash_slh_verify(M, SIG, ctx, PH, PK)
```

Flow:

```text
PHM <- PreHash(M)
M'  <- prefix || ctx || PHM

Call slh_verify_internal(M')
```

---

# 14. Signature Structure

```text
SIG = (
    R,
    SIG_FORS,
    SIG_HT
)
```

Where:

```text
SIG_HT = sequence of XMSS signatures
```

Each XMSS signature contains:

```text
(
    WOTS+ signature,
    authentication path
)
```

---

# 15. Important Security Properties

## Randomized Signing

```text
R = PRFmsg(SK.prf, opt_rand, M)
```

Prevents:

* Multi-target attacks
* Side-channel leakage amplification

---

## Statelessness

No persistent signing state required.

Security relies on:

* Huge hypertree
* Randomized digest mapping
* FORS subset selection

---

## Domain Separation

Achieved using:

* ADRS
* PK.seed
* Type-specific hashing
* Layer/tree indices
* Context prefixes

---

# 16. Minimal End-to-End Signing Flow

```text
Generate R
    ↓
Hmsg(R || M)
    ↓
Extract md, idx_tree, idx_leaf
    ↓
FORS sign md
    ↓
Recover FORS PK
    ↓
Hypertree signs FORS PK
    ↓
Output final signature
```

---

# 17. Minimal End-to-End Verification Flow

```text
Recompute digest
    ↓
Recover FORS PK
    ↓
Verify hypertree upward
    ↓
Recover top root
    ↓
Compare with PK.root
```