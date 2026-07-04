# Corner cases

The governance, consensus, and sync corner cases an application author hits, each with the design limit that bounds it. Every item has a regression test in the suite named below.

## Governance (membership)

The tally is deterministic; the member set is a function of the set of committed votes, not their order. Suite `GovernanceTests`.

- Quorum is 2f+1 of the current member count and recomputes as the set grows or shrinks.
- A non-member's vote is ignored.
- A member may vote to remove itself.
- Add then remove the same target returns to the prior set.
- Add votes carry data; voters must agree on the same data or no proposal reaches quorum.
- The cap blocks addition even at quorum; cap == genesis means no growth.
- The floor blocks removal; the last member (or below the floor) cannot be removed.
- Duplicate votes from one voter count once.

At the node level (`ConsensusTests`), a committed governance vote transitions the validator set at +2 and the chain keeps committing across the transition, for both Add and Remove. A bad-signature or non-member vote is rejected at the envelope (`BaseTests`).

Deliberate limits:

- Removing enough members to drop live participation below quorum stalls liveness but never corrupts state. This is the BFT bound. The floor guards the state-level minimum.
- A validator voted in participates only once running and synced; until then the set counts it absent, so quorum must be reachable among the present members.

## Consensus + composite state

Suites `ConsensusTests`, `BaseTests`, `LedgerTests`, `RegistryTests`.

- One decided value per height; >=2/3 commit certificate; determinism of the composite AppHash across replicas.
- Every replica receives the decided value (parts payload) and can apply it; no decide-miss in a connected cluster.
- A value must build on the committed parent AppHash; a stale-parent value is rejected.
- Malformed envelope, bad governance signature, non-member voter, and app-rejected payload are all rejected.
- The Tendermint algorithm itself (equivocation, partitions, timeouts, crash+WAL replay) is proven by malachite-cpp's own simulator; Hyle does not re-prove it.

## Stress, scale, and faults

Suite `StressTests`.

- A large validator set (N=24) converges over multiple heights; every node agrees on the composite AppHash and the applied value per height. The in-process broadcast is O(N^2) with an ed25519 verify per delivered vote, so large N is bounded, not free.
- 3f+1 validators with f fail-stop still commit via the 2f+1 survivors; rounds led by a crashed proposer time out and move on.
- With f+1 down, the 2f survivors cannot reach quorum: the chain stalls (liveness lost) but never diverges (safety holds).

## Adversarial network simulation

Suite `SimTests` (`tests/sim_cluster.h`): a discrete-event message bus with a seeded PRNG, per-node Byzantine roles, and a deadline-based timeout model. Two invariants asserted every run: safety (no two correct nodes decide differently at a height) and liveness (the goal height commits). The sim also models block-sync so a scattered laggard recovers.

- Reliable async baseline commits and agrees.
- Heavy delay + reorder + duplication (no loss) converges.
- A Byzantine proposer proposing garbage is rejected; the round rotates to an honest proposer.
- An equivocating proposer is denied a quorum; safety holds.
- A nil-voting minority never commits live and recovers by block-sync; the honest quorum carries every height.
- Packet loss (drop + delay + dup until a stabilization tick) scatters nodes; they recover by block-sync and agree.
- Maximum gate: N=200 with a garbage proposer, an equivocator, 8 crashed, and 10 nil-voters over a delay/reorder/dup network; the 192 non-silent nodes reach the goal and agree.

Deliberate limits:

- Sustained packet loss is not combined with N=200: each round is an O(N^2) ed25519-verify storm and loss widens block-sync past the time budget. Loss-liveness is proven at N=10; the N=200 gate proves scale + Byzantine faults + async delivery.

## Snapshot + block sync

Suites `SyncTests`, `SnapshotTests`, `LedgerTests`, `StateTests`.

- Blocks are retained with their commit certificate + proposer in a bounded, pruning window.
- Near-behind: a node within the window replays blocks, no snapshot.
- Snapshot on cadence; blocks behind the latest snapshot are pruned so it always bridges to the tip.
- Far-behind / fresh: adopt the latest snapshot, then replay the blocks after it; the first block's certificate authenticates the snapshot via the parent-hash guard.
- Validator-set change during catch-up: a joiner verifies each block's certificate against the set operative at that height, derived from the governance it is syncing.
- Chain-scoped attestations: `adopt_snapshot` folds `chain_id` into the expected AppHash, so an attestation quorum from another chain cannot be replayed.
- `restore` is atomic: a malformed, truncated, or non-canonical snapshot is rejected and leaves existing state unchanged.

Deliberate limits:

- A snapshot at height S is servable only once block S+1 exists (S+1 carries AppHash(S)). Blocks flow continuously, so this is a sub-one-height window.
- Weak subjectivity: a fresh joiner trusts the validator set it is handed (the snapshot's `next_set`) as its checkpoint, as every BFT joiner must. `adopt_snapshot` verifies a quorum of attestations against an out-of-band trusted set; `restore_snapshot` takes `next_set` as given and verifies forward by certificate. A forged `next_set` is defeated only by `adopt_snapshot`'s trusted checkpoint, as CometBFT state sync requires trust_hash/trust_height.

## Adversarial input

- A decoded list count cannot exceed the remaining bytes (`wire::Reader::count` self-validates), no decoder reserves on an untrusted count, and `verify()` / `restore_snapshot` reject a malformed key or snapshot rather than letting an exception escape.
- `sync_value` records the certificate's proposer, so a caught-up node credits the same proposer as the live nodes: no economy fork on synced heights.
- The snapshot carries the complete governance state (in-flight vote tallies and the H+2 validator set), so a membership proposal straddling a snapshot converges on a joiner.

## Out of scope (outer layers)

Real transport (loss/reorder/dup on sockets), mempool/gossip, and RPC are outer layers with their own harnesses; the in-process mock proves the store + sync + consensus logic they carry.
