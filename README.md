# sov-redteam

A **standalone adversarial harness** for the [SOV chain](https://github.com/cloudzombie/sov).
It builds a real in-process chain — the actual consensus code (`produce_block` /
`import_block`), the same path a node runs — and throws a battery of theoretical attacks
at it, then reports which **defenses held**. This is *not* the unit-test suite; it's a
red team you run on demand.

The consensus crates come straight from `cloudzombie/sov` as git dependencies, pinned in
the committed `Cargo.lock`. Nothing is vendored, mocked, or stubbed: every verdict below
is what real consensus actually did with adversarial input.

```
cargo run --release            # in-process: attack a private replica of consensus
```

Each attack is judged **DEFENDED** (the chain rejected it or resolved it correctly),
**VULNERABLE** (the attack succeeded — a real finding), or **INFO** (a property worth
disclosing that is not a free win for the attacker). The process exits non-zero if
anything is VULNERABLE, so CI or a release gate can consume it.

## Install (macOS, Apple Silicon)

Every tag publishes a signed-by-checksum `aarch64-apple-darwin` build, produced on an
arm64 runner that ran the tests *and* the full gauntlet before publishing.

```sh
tag=v0.1.0
name=sov-redteam-$tag-aarch64-apple-darwin
curl -LO https://github.com/cloudzombie/sov-redteam/releases/download/$tag/$name.tar.gz
curl -LO https://github.com/cloudzombie/sov-redteam/releases/download/$tag/$name.tar.gz.sha256
shasum -a 256 -c $name.tar.gz.sha256
tar -xzf $name.tar.gz && ./$name/sov-redteam
```

Or build from source (needs `cmake` for RandomX): `cargo build --release`.

## Live-fire modes

The in-process battery is the default. The same binary also attacks a REAL running node:

```sh
sov-redteam --target <host[:port]>              # front door: JSON-RPC
sov-redteam --target <host[:port]> --p2p        # back door: join P2P as a hostile peer
sov-redteam --target <host[:port]> --funded     # funded adversary (key from SOV_REDTEAM_KEY)
sov-redteam --target <host[:port]> --gauntlet   # try to drain the live steal-the-pot account
```

The front-door probe is side-effect-free — every transaction it sends is rejected at
admission, so nothing lands in the target's mempool.

## What it attacks

| Category | Attack | Defense under test |
|---|---|---|
| **time** | timewarp: backdate to median-time-past | BIP-113 MTP rule vs. difficulty gaming |
| **time** | pre-genesis timestamp | lower timestamp bound |
| **time** | EDA farming: future-stamp for easier difficulty | easing capped at `2^EDA_MAX_HALVINGS`; eased blocks weigh less |
| **tamper** | state_root / tx_root / timestamp / nonce / bits / prev_hash | the PoW seal binds every header field |
| **supply** | coinbase redirect (steal the reward) | seal covers `proposer` |
| **forgery** | corrupted signature, malleability, wrong key, overspend, `u128::MAX` overflow | signatures fail closed; checked arithmetic; failed transfers revert |
| **post-quantum** | valid Ed25519 half + broken ML-DSA half | **hybrid conjunction** — a future Ed25519 break alone can't forge |
| **replay** | import the same block twice; reuse a spent nonce | no double-advance / double-credit |
| **consensus** | equal-work fork, both arrival orders | deterministic tie-break (no permanent fork with thin hashpower) |
| **flood** | 20k-transaction flood into one block | elastic block-size cap |
| **foreign-chain** | *build your own chain and spend it onto the honest chain* (4 vectors) | see below |

### foreign-chain injection

An attacker can always mint a private universe — its own genesis, its own balances, its
own fabricated proof of work — for free. The only question is whether any artifact of it
can cross onto a chain that never agreed to it.

| Vector | What it does | Result |
|---|---|---|
| `foreign_genesis_block_import` | mines a real sealed block on a chain with a different `chain_id`, offers it to an honest node | **DEFENDED** — `PrevHashMismatch`; its parent is the attacker's genesis |
| `extract_tx_from_foreign_chain` | mints 1,000,000 SOV in its own genesis, spends it there for real, lifts the identical signed tx onto the honest chain | **DEFENDED** — mined but REVERTED; the account holds nothing here |
| `fabricated_heavier_branch` | pins a checkpoint far above the tip, then feeds blocks below it whose seals do not meet target | **DEFENDED** — `PowInsufficient`; the assumevalid skip is ancestry-gated (`is_linked_to_checkpoint`), not height-gated |
| `private_reorg_double_spend` | pays a victim, confirms it, then reveals a privately-built branch that omits the payment | **INFO** — a *lighter* branch cannot reorg it out; an *equal-work* branch does, via the deterministic smaller-tip-hash tie-break (see below) |

The attacker's account is an **implicit** id (`hex(blake3(pubkey))`), so it is key-bound
and genuinely the same account on both chains. Only the BALANCE is fabricated, and only
on the attacker's own genesis — which is what makes the value defense the thing actually
under test, rather than an identity check.

## Disclosed, not buried

At **exactly equal** cumulative work, SOV's fork choice adopts the branch with the
smaller tip hash — the deliberate convergence rule that stops equal-work miners
fork-warring forever. The harness probes that boundary and reports honestly: an
equal-work private branch *did* reverse a 2-confirmation payment. It still costs the
attacker work equal to the honest chain's over the reorg span (~parity hashpower), so it
is not a free double-spend — but at parity it is deterministic rather than a coin flip,
and an attacker can grind extra seals and publish the smallest-hash one. That is reported
as **INFO**, never dressed up as a green.

## Honest scope

We cannot run Shor's or Grover's algorithm, and we cannot forge a BLAKE3 collision —
no one can. What this proves is that the chain **fails closed**: every forgery a
classical attacker can produce is rejected, the seal binds the whole header, and the
hybrid signature needs **both** halves — so even a future break of Ed25519 alone leaves
ML-DSA-65 (FIPS-204) stopping the forgery.

If a defense cannot be exercised through the real API without a mock, the harness emits
`Outcome::info` and says so. It never fabricates a pass. A real VULNERABLE finding is a
success of the tool, not a failure of the chain's authors — it is the entire purpose.

## Adding an attack

One function returning an `Outcome`, registered in `run_all()` in `src/lib.rs`. It must
drive real `produce_block` / `import_block` / transaction validation; an attack that
asserts against a stub proves nothing and will be rejected in review.

## Releases

Tag `vX.Y.Z` → the release workflow builds on a **macOS 15 arm64** runner, runs the
crate's tests and the full gauntlet on that hardware, verifies the binary really is
`arm64` (`lipo -archs`), and publishes a tarball plus a SHA-256 with the gauntlet report
embedded in the release notes. CI additionally runs the battery daily, because the
consensus it attacks lives in another repository and moves without this one changing.
