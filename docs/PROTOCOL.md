# Overstory Protocol v1

Technical specification · Mainnet collection · 20 October 2026

Overstory is a metaprotocol on the Zcash transparent pool. It defines how an inscription
is written, who owns it, how a collection is declared, how a mint joins a collection, how
the artwork of a mint is derived, and how an item is sold without escrow. Every rule below
can be evaluated by anyone replaying the chain; protocol validity does not depend on the official website. Public interfaces and the optional assisted-mint service remain operational services, distinct from the chain rules.

## Abstract

Overstory defines reproducible generative artwork and transferable ownership on Zcash's transparent transaction graph. An authenticated commit–reveal envelope binds the inscription data to its spending script. Collection membership is determined by canonical transaction order, a fixed supply, a start height and a required mint payment. A seed derived from the inscription transaction and its completion block produces the artwork through an inscribed deterministic renderer. Ownership follows a transparent output; secondary sales can settle atomically without custody of the item by a marketplace.

## Official collection

| Parameter | Mainnet value |
|---|---|
| Collection ID | `7255d20a586fa665c5d66a61b71f2f0a31f715597922e8e30b526f759faf44a2i0` |
| Renderer ID | `51f848e31c5bf0ed38c5936129915a24fb08a85074c4c0d650be5de47671eec0i0` |
| Supply | 3,000 valid mints |
| First eligible block | 3,526,433 |
| Mint payment | 0.05 ZEC (5,000,000 zatoshis) |
| Mint recipient | `t1f7JPjEc8drDirsJfpMwbcdrWCHS7whgrt` |
| Per-address limit | None |
| Renderer source SHA-256 | `67b00f3dedee8a93014b6e8da71795f1766d91b5028892d587140aa96f221f42` |

The renderer and collection declaration are confirmed on mainnet. The start block is authoritative; a calendar estimate is not a consensus condition. These parameters identify the official collection, while the following sections define the general protocol. A name alone does not identify a collection.

The optional assisted-mint invoice totals 0.10 ZEC, including the mint payment and minting network fees. The sending wallet's transfer fee is additional. An invoice or payment does not reserve a mint number or guarantee membership. The official market remains closed during minting and opens only after sellout, index verification and a separate operational decision. Its 2% buyer fee is a marketplace policy, not a royalty enforced on all protocol transfers.

## 1. Networks and scope

Zcash mainnet, testnet and regtest, transparent pool only. Inscription ownership follows transparent outputs. A spend without a transparent non-data output terminates tracking as specified in section 3.3; the presence of a shielded bundle alone does not override a valid transparent carrier.

Transaction versions 5 and 6 are valid carriers. Builders derive the consensus branch id,
version group id and expiry height from the chain they target.

### Replay completeness (implementation constraint)

The index records `replay_from` for a fresh replay, bound to the committed tip height and hash. A legacy index or a stale marker from an older writer is `unknown`; a replay starting after block 1 remains `partial`. Rollback restores this metadata atomically with indexed state. These are local provenance labels, not independent validation: a copied database or a compromised node is not made trustworthy by its metadata. API `healthy` indicates current chain checks, not complete or independently audited history. `index_history.independently_verified` remains false.

A recent collection deployment block is not a safe standalone replay starting point.
The renderer may predate it, multipart reveals may cross that boundary, and older
carriers may later merge with a collection item. Omitting that state can change
ownership and single-carrier checks. The current parser does not enforce a v5/v6-only
historical cutoff; the transaction-version statement above must not be used to infer
that no earlier envelope or carrier state exists.

Full replay remains the reference. A nonzero `start_height` on an empty service index
is an explicitly scoped test/replay setting, not proof of complete history. Raising it
above the next unprocessed block on an existing index is rejected. The CLI's
`index --max-blocks N` bounds work while retaining contiguous replay and durable restart;
it does not skip history. A production acceleration checkpoint requires a separately
verified complete state, a pinned chain anchor and explicit reorganization handling.
The official self-mint workflow uses full replay; the project does not distribute an index checkpoint or provide a self-mint RPC service.

## 2. Inscriptions

An inscription is content bytes plus a content type, written through a commit
transaction and one or more reveal transactions. The push-only envelope retains the
ord-style field layout. New builders use an authenticated redeem script that enforces
every envelope stack value at consensus validation, in addition to a whole-content
commitment. The earlier drop-only redeem script remains readable for historical replay;
it is not the authenticated format.

### 2.1 Commit

The commit transaction creates a P2SH output whose script hash commits to the exact
redeem script below. Let `E` be the envelope stack values before the signature:
`["ord", totalPieces, contentType, pieceIndex, piece, ...]`. Numbers here mean their
actual pushed byte strings, as specified in section 2.2.

```
PUSH <33-byte compressed pubkey>
OP_CHECKSIGVERIFY
PUSH <32-byte C>
OP_DROP
for each item in reverse(E):
  OP_SHA256
  PUSH <32-byte SHA256(item)>
  OP_EQUALVERIFY
OP_DEPTH
OP_0
OP_EQUALVERIFY
OP_1
```

`C = SHA256("UZRD1" || contentType || 0x00 || content)`, where `contentType` is the
exact ASCII bytes pushed in the envelope and `content` is the complete content.
The script is reconstructed exactly from the parsed fields, public key and `C`.
Each reveal authenticates its own header and pieces. The final depth check rejects
extra stack values, including an unverified prefix. The builders sign with
`SIGHASH_ALL`, binding the output amounts and scripts, including mint payment and
any explicit recovery marker.

Changing `ord`, a header field, a piece index or piece bytes fails a script hash
comparison. Changing the expected hashes or verification code changes the redeem
script and fails the original P2SH commitment. This does not make an incorrect
whole-content `C`, an unavailable mint or an invalid collection request valid;
those remain metaprotocol checks.

### 2.2 Reveal

Input 0 of a reveal transaction spends a commit output. Its scriptSig is push-only:

```
PUSH "ord"
PUSHNUM totalPieces          1..255
PUSH contentType             3..96 ASCII bytes containing "/"
repeated for each piece in this transaction, at most 4, indexes descending:
  PUSHNUM pieceIndex
  PUSH piece                 240 bytes; only index totalPieces - 1 may be shorter
PUSH signature
PUSH redeemScript
```

The builder encodes `PUSHNUM n` as OP_0 for 0, OP_1..OP_16 for 1..16, and a
one-byte data push for 17..255. These are protocol byte values, not arbitrary
Script-number encodings: zero is the empty stack byte string, and nonzero values
are exactly one byte. A pushed byte `0x00` is not equivalent to OP_0 and is rejected
for authenticated piece index zero.

Authenticated decoding uses the actual push-stack values. Equivalent push-only
encodings producing exactly the same values are accepted, including direct pushes,
PUSHDATA1/2/4 and small-integer opcodes where their stack bytes agree. Each pushed
item is at most 520 bytes and the script is at most 10,000 bytes. Opcode encoding
alone must not cause a consensus-valid authenticated envelope to lose its meaning.
Historical drop-only decoding retains its original canonical-encoding rule.

Content is split into pieces of 240 bytes. Piece `totalPieces - 1` is pushed first, piece 0
last. Reassembly concatenates pieces by ascending index. Maximum content size is
255 * 240 = 61,200 bytes.

### 2.3 Chains

When more than four pieces are needed, reveals are chained:

- the genesis reveal spends the commit output and carries the highest indexes;
- each continuation reveal spends output 0 of the previous reveal, which pays a P2SH
  output built with the same rules as a commit: the same `C`, but expected hashes
  for that next reveal's full header and its own pieces;
- the completion reveal carries piece 0.

Every reveal repeats the full header. Every redeem script in a chain commits to the same `C`.

### 2.4 Validity

An inscription is valid when every piece index is unique and within range, pieces
arrive in contiguous descending order across the chain, reassembly yields exactly
`totalPieces` pieces, and `C` in every redeem script equals the commitment computed
over the reassembled content. Only the highest content index may contain a short
piece; piece zero is the last transmitted piece, not necessarily a short piece.

An inscription is `authenticated` only if every reveal uses the authenticated script
and its actual spent output proves the P2SH commitment, with consistent headers and
`C` across the chain. A matching whole-content hash alone is insufficient.
Incomplete chains remain incomplete and their content is not served.

Historical compatibility is explicit: earlier drop-only scripts with a valid `C`
remain the committed `v1` family but have `authenticated = false`; their existing
collection semantics remain available for replay. Envelopes without a verifiable
commitment are `legacy` and cannot join collections. Existing records lacking the
new flag default to false; they must not be relabeled authenticated without replay.
New production collections require the authenticated renderer, deploy and mint
path described in section 4. Old-format mints cannot join those collections.

### 2.5 Identity

Inscription id: `<genesis txid>i0` (display-order hex). One inscription per genesis
transaction. The completion transaction is the reveal that carries piece 0; for a single
reveal it is the genesis transaction.

### 2.6 Explicit recovery of an expired continuation

Recovery preserves the original authenticated envelope because its values are
required to spend the P2SH output. It must not accidentally complete an inscription.
The recovery builder uses two transparent outputs, both bound by `SIGHASH_ALL`:

```
output 0: value 0; script OP_RETURN PUSH "UZRD-RECLAIM"
output 1: refund amount to the selected transparent refund address
```

The exact marker script is `6a0b555a52442d5245434c41494d` (11 marker bytes).
Output zero is a data output, so this spend cannot create or complete a new
inscription under section 3.1. Spending a pending continuation consumes its pending
state. This is not a recovery mechanism for an already completed inscription.

The caller must establish expiry of the original transaction plan, canonical
confirmation of the selected original output, absence of a completed inscription,
and exclusive reservation before signing. Authenticated recovery fees use the full
envelope and a conservative 73-byte signature budget with two outputs; the remainder
must meet the refund dust threshold. The saved recovery plan has version 2. Ordinary
refund plans and historical drop-only recoveries retain version 1 and their previous
single-output behavior. An unaffordable recovery remains an outstanding liability.

## 3. Ownership

### 3.1 Genesis

At completion, the inscription is owned by output 0 of the completion transaction, which
must be a transparent, non-data output. Its value is the postage (546 zatoshis by
convention).

### 3.2 Transfer

When the carrying output is spent, the inscription moves to the first transparent,
non-`OP_RETURN` output of the spending transaction, in output-index order.

### 3.3 Terminal states

If the spending transaction has no transparent non-data output, tracking ends. If that
transaction carries any shielded bundle the state is `shielded`, otherwise `burned`. Both
are permanent; later transactions never revive an inscription.

## 4. Collections

Declarations are inscriptions with content type `application/json` whose content is a
JSON object with `"p": "overstory"`. Any other content is an ordinary inscription.

### 4.1 Deploy

```json
{"p":"overstory","v":1,"op":"deploy",
 "name":"...","supply":3000,"max_per_addr":2,"price":200000,
 "pay":"t1...","start":3500000,"renderer":"<inscription id>"}
```

| Field | Meaning |
|---|---|
| `name` | display name, informational |
| `supply` | maximum number of valid mints, 1..100000 |
| `max_per_addr` | maximum valid mints per destination address; 0 = unlimited |
| `price` | zatoshis that a mint must pay to `pay`; 0 = free |
| `pay` | transparent address receiving mint payments |
| `start` | first height at which mints are valid (never below the deploy's completion height + 1) |
| `renderer` | inscription id of the renderer specification and reference source |

The collection id is the deploy inscription id. Names are not unique and carry no
authority. A deploy is valid if it parses, `supply` is in range and `pay` is a transparent
address. Invalid deploys are ignored.

An authenticated deploy requires a completed authenticated `text/*` renderer
inscription and marks its collection `authenticated = true`. Empty renderers are
allowed only for private Regtest development collections. Production launch must
use the authenticated deploy path; the authenticated flag is derived from the
inscription, not a self-reported JSON field.

### 4.2 Mint

```json
{"p":"overstory","op":"mint","d":"<deploy inscription id>"}
```

A mint inscription is a valid member of collection `d` if, evaluated in chain order
(block height, then transaction index within the block), all of the following hold at the
moment its completion transaction is processed:

1. `d` names a valid deploy;
2. the completion height is at least the collection's `start`;
3. fewer than `supply` valid mints exist;
4. the destination address (owner of output 0 at completion) has fewer than
   `max_per_addr` valid mints, when `max_per_addr` is nonzero;
5. when `price` is nonzero, the completion transaction pays at least `price` zatoshis in
   total to `pay`;
6. an authenticated collection requires an authenticated mint inscription.

A valid mint receives `number = (previous valid mint count) + 1`. A mint that fails any
rule is an ordinary inscription: it keeps its content and ownership but is not a member,
and its fees are not refunded. Membership is decided at completion on the canonical chain. A chain reorganization rolls back affected state and may change membership, numbering, ownership and the artwork seed.

### 4.3 Seed

```
seed = SHA256( genesis_txid || completion_block_hash )
```

Both values are the 32-byte identifiers in display order (the byte order of the hex shown
by explorers). The seed is the only input to the renderer.

## 5. Rendering

The renderer specification is published as an inscription (the `renderer` field of the
deploy). Its output for a seed is a 64x64 matrix of palette indexes; the SHA-256 of that
matrix, row-major, is the canonical image hash. PNG or any other encoding is presentation
only.

The renderer is required to be deterministic across implementations: integer-only
arithmetic, a frozen 1024-entry sine table, and xoshiro256** streams seeded through
splitmix64 from `SHA256(seed || streamTag)`. The reference implementation is the
inscribed source; an independent implementation must reproduce the matrix hash of the
published test vectors exactly.

## 6. Listings and sales

A listing is a signature by the current owner over the carrying output with
`SIGHASH_SINGLE | SIGHASH_ANYONECANPAY` (0x83, ZIP 244 semantics). It commits to the
carrier input and to the output at the same index, the seller payout.

A listing document carries: carrier outpoint, value and scriptPubKey; seller public key;
payout address; price; expiry height; the DER signature. Because the signature commits to
the transaction's expiry height, the listing expires by consensus.

A purchase is one transaction assembled by the buyer:

```
inputs : [buyer funds, carrier]
outputs: [destination (postage), seller payout (price), buyer change]
```

The buyer verifies the seller signature against the sighash of the assembled transaction,
signs its own inputs and broadcasts. Either the whole transaction confirms or nothing
happens; no party holds anything for the other. A listing stops being usable when the
carrier is spent (sale, transfer to self, or any other spend) or when the expiry height
passes.

## 7. Indexer requirements

- Process blocks in height order and transactions in block order.
- Parsers impose hard bounds: authenticated scriptSig at most 10,000 bytes with
  individual pushes at most 520 bytes; historical decoding retains its 1,650-byte
  limit. Chain length is at most 64 reveals and content at most 61,200 bytes.
  Malformed data must never be served as valid inscription content.
- Two independent indexers replaying the same chain must produce the same set of
  inscriptions, owners, collections, members, numbers and seeds. Replay from genesis must
  equal incremental indexing.

## 8. Verification, security model and fees

The reference implementation includes regression coverage for envelope mutation, equivalent push encodings, authenticated collection membership, historical replay and explicit recovery. The official renderer and collection have been checked against their confirmed mainnet bytes. Independent application-index replay has been compared at fixed canonical-chain anchors. These checks are evidence about tested versions and anchors; they are not a guarantee of future correctness or an independent implementation of Zcash consensus.

The protocol relies on Zcash consensus, signature and hash security, complete canonical-chain data, and faithful implementation of these rules. Reorganizations require rollback and replay. The seed is reproducible but is not an unbiased randomness beacon: transaction selection and block production can influence its inputs. Ordinary wallets may spend a carrier as normal funds; use dedicated addresses and inscription-aware tools. Lost spending keys cannot be recovered by the protocol. Invalid, premature or excess-supply mints can spend funds without obtaining collection membership.

Source code and preparation instructions: https://github.com/overstorycash/overstory. The technical rules apply independently of website availability. Assisted-mint custody, support and refunds are service responsibilities and must not be confused with a consensus refund mechanism.

Reveal fees follow ZIP 317: 5,000 zatoshis per logical action, at least two actions.
The larger authenticated redeem script changes the input size. Builders calculate
each reveal or recovery fee from its complete scriptSig size and output count,
using a conservative signature length. Earlier byte counts and fixed example fees
for drop-only reveals are not estimates for this revision.
