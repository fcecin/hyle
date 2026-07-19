# CometBFT / ABCI mapping

Hyle's surface against a CometBFT node + ABCI app. Each item is COVERED, OUTER (belongs to a layer above Hyle: transport / mempool / RPC), or GAP.

## Consensus

- Round and commit timeouts: malachite owns them (defaults; not a Node knob). COVERED.
- create_empty_blocks: a value commits every height (empty payload allowed). COVERED.
- Proposer selection: deterministic, surfaced to the app via `ApplyContext.proposer`. COVERED.
- Equivocation / byzantine minority: malachite detects and excludes. COVERED. Slashing is app policy: GAP (no slashing hook).
- Vote extensions: supported by malachite, not surfaced by Hyle. GAP.

## App interface (ABCI)

- CheckTx: `validate_payload`, checked before prevote. COVERED (a real mempool is OUTER).
- FinalizeBlock/DeliverTx: `apply_payload` with `ApplyContext {height, proposer}`. COVERED.
- Commit / AppHash: the composite AppHash committed by consensus (parent-hash lag). COVERED.
- InitChain: no hook; the app starts empty. GAP (workaround: a genesis payload at height 1).
- Validator updates: base-native governance (members vote), not app-returned. Different by design.
- Query: OUTER (RPC). The app exposes its own in-process read accessors.
- Native token: the canonical layer-2 app issues credit by per-block validator autofill plus governance sudo out of the mint sentinel; it does not reward `ApplyContext.proposer` and there is no PoW mint.

## State sync

- OfferSnapshot / ApplySnapshotChunk: snapshot store + `adopt_snapshot` / `restore_snapshot`, served live over SnapReq/SnapResp by `hyle::services::Runtime`; each server includes its own attestation and the joiner pools them to a >2/3 quorum. The snapshot is the complete consensus state (app + governance member set and in-flight vote tallies + the H+1 and H+2 validator sets). COVERED.
- trust_height / trust_hash: the joiner's current validator-set knowledge (genesis for a fresh joiner) is the trusted checkpoint the attestation quorum is verified against. COVERED.
- Snapshot chunking: a snapshot is served as one blob and refused above the transport's `max_message`. GAP for large states.
- Block sync: a behind node pulls retained blocks over ValueReq/ValueResp and replays them under certificate verification; a pruned tail falls back to snapshot sync. Driven by `Runtime` over any Transport. COVERED.

## Storage / pruning

- Block retention window: `NodeConfig.block_retention` / `snapshot_interval`. COVERED.
- No disk: by design, with one exception, the vote WAL below. App/governance state is RAM-only and recovers via state-sync.
- Double-sign protection across a crash: the optional vote WAL (`NodeConfig.data_dir`) persists only the current undecided height's votes to a small self-erasing file, truncated on each commit. Not app-state durability. With no `data_dir` the WAL is in-RAM (no crash protection).

## Genesis / chain params

- Genesis validator set + initial height: malachite `Config`. COVERED.
- chain_id: `NodeConfig.chain_id` prefixes the composite AppHash, so a value built on another chain's state is rejected. Ops are also scoped per-op by domain tags. COVERED.
- Max value size: `NodeConfig.max_value_bytes`; `accept_proposed` rejects a larger value. Decoders are additionally bounded (a decoded count cannot exceed the remaining bytes).
- Gas / execution metering: N/A (no VM). The app bounds its own op cost.

## Networking / ops

- P2P transport, peer discovery: OUTER (`docs/TRANSPORT.md`).
- Mempool + tx gossip: OUTER. `submit` is a local pending queue.
- RPC / gRPC: OUTER.
- Metrics: GAP (light) beyond `decide_misses` / `block_count`.
- Logging: vendored `blog` (Boost.Log), modules ship disabled; enable via `blog::set_level("hyle.node", blog::debug)`.
