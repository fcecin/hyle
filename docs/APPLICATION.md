# The Application seam

The contract between the Hyle base (layer 1) and an application (layer 2). The base is generic BFT consensus plus governance plus snapshot state sync; it does not interpret the application's bytes. The application implements this seam and nothing else: it never sees a governance op, a signature, a certificate, a validator set, or the network.

## Interface

An application implements `hyle::StateMachine` (`include/hyle/core/state_machine.h`):

- `Bytes build_payload(uint64_t height)`: proposer only. Produce this height's application payload. The base wraps it in the value envelope with the parent AppHash and any governance ops.
- `bool validate_payload(View payload)`: return false to vote nil. Check the payload against the current committed state. Must not mutate state.
- `void apply_payload(const ApplyContext& ctx, View payload)`: apply the decided payload. `ApplyContext` carries the committed consensus facts the base surfaces: `height` and the block `proposer` (32-byte key, or zero if unobserved). Both are identical on every replica and may be used deterministically (e.g. minting a block reward to `ctx.proposer`). The state-sync path reproduces the same context.
- `Bytes snapshot() const`: canonical serialization of the application's own state. The base hashes it into the AppHash and ships it in a snapshot.
- `void restore(View)`: replace the application state from a `snapshot()` serialization. Must be atomic: on malformed, truncated, or non-canonical bytes it must throw (`wire::Error`) and leave the existing state unchanged (decode into a temporary, swap on full success). The base treats a throw as a clean rejection.

## Requirements

- Determinism. The same payload applied at the same height must produce a byte-identical result on every replica. `snapshot()` must be canonical and must round-trip with `restore()`.
- No hidden inputs. `apply_payload` and `snapshot` may depend only on prior applied payloads. No wall-clock, no map iteration order, no randomness, no host state.
- `validate_payload` is a predicate; it must not change state.

## The composite AppHash

The base computes, over the committed state:

    AppHash = sha256( chain_id ++ governance_canonical ++ application.snapshot() )

The application supplies only the last operand and has no `app_hash` method. `chain_id` scopes it to this chain; `governance_canonical` covers the member set and in-flight vote tallies. A value for height H embeds AppHash(H-1); the base checks it and the commit certificate certifies it.

## Reference

`hyle_services` is the canonical layer-2 application. The plain KV store (`include/hyle/services/kv/kv_state_machine.h`) treats a payload as an ops batch and snapshots the sorted key/value serialization. The economy (`include/hyle/services/app.h`) layers accounts and K,V entries with rent over that generic store and adds transfers, lazy rent, opportunistic eviction, names, and governance/sudo; credit is issued by per-block validator autofill plus sudo out of the mint sentinel, not by proof-of-work. A mock (`tests/mock_state_machine.h`) implements the contract trivially to test consensus in isolation.
