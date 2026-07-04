# Hyle

An in-RAM BFT consensus key-value substrate, built on malachite-cpp. The name Hyle is a trademark of the author.

A single BFT chain whose replicated state machine is an in-memory key-value store with height, blocks, membership governance (members vote to add and remove members), a per-height state hash committed by consensus, and snapshot-based state sync for joiners. Shaped like a CometBFT node, but the application is fixed: a synchronized consensus data store. No bytecode VM.

## Locked decisions

- No disk. The replicated state lives entirely in RAM. Durability is replication across stable peers, not local persistence. No WAL for app state and no on-disk snapshot. (The one optional on-disk artifact is the small vote WAL for double-sign protection across a crash.)
- Membership is the durability and catch-up mechanism. A node that stops participating is ejected. A joiner downloads a current RAM snapshot, verifies the >=2/3 commit certificate over its state hash, adopts state and height, and validates from there. No historical block replay.
- One Hyle chain is one BFT store that survives losing under 1/3 of its validators. Population-level resilience (the same key across multiple chains) is an application layer above Hyle, not inside it.
- Standalone first, pluggable later. The network is self-contained (a persistent TCP mesh over Boost.Asio behind a `hyle::Transport` seam). Pluggable transport is a later refactor; the seam exists from day one.
- Base-native governance, composite state. Governance is solved once at layer 1. `AppHash = hash(chain_id ++ governance ++ application)`. The base owns the value envelope `[parent AppHash][gov ops][opaque app payload]`, the composite hash, and the +2 validator-set schedule; the app is payload-only and never sees a governance op. One-height lag (value H embeds AppHash(H-1)).
- Snapshot state sync: a joiner adopts the composite state at a height, trusting a quorum of member attestations over the AppHash. No history replay.
- Native token. The chain has its own native credit, self-minted by block reward to each committed block's proposer (core surfaces the proposer via `ApplyContext`; the app mints). It is not reconciled against any server's local credit; the bridge to an external market is off-chain. The economy is layer 2 (`kv`: `Ledger`).

## Dependencies

Minimum: malachite-cpp + CryptoPP + Boost.

- malachite-cpp: the BFT consensus core (IO-free; the consumer supplies transport, the value/state store, state-sync bytes, and the sign/verify crypto callbacks). Needs a Rust toolchain on PATH.
- CryptoPP: ed25519 + sha256 for the malachite sign/verify callbacks and the per-height AppHash.
- Boost: `unordered_flat_map` (the RAM state container), Boost.Endian (under `hyle::wire`), Boost.Asio (the TCP validator mesh), Boost.Test. All but Asio are header-only here.
- Byte packing is `hyle::wire` (`include/hyle/core/wire.h`): an explicit canonical header-only encoder on Boost.Endian. The public API passes opaque bytes as `std::span<const uint8_t>` in and `std::vector<uint8_t>` out, matching malachite-cpp. Keep `hyle::wire` Hyle-type-free so it can lift into a shared packing library later.
- Not MINX: MINX is a PoW / anti-spam / RUDP substrate; Hyle's membership is BFT-governed, not PoW-gated.
- Not logkv: Hyle uses no Store, keeps no disk, and wants explicit canonical encoding for the AppHash rather than logkv's Store-coupled serializer.

## Build

```
./build.sh debug                 # build (fetches deps; needs Rust for malachite-cpp)
./build.sh debug --test          # build + tests
./build.sh debug --test Smoke*   # one suite/case (Boost.Test filter)
./build.sh release
./build.sh rm                    # wipe build/
```

Redirect build output to a file and grep it; do not tail the live pipe.

## Layout (three layers: core, services, morphe)

```
include/hyle/core/       layer 1 (lib: hyle): wire, crypto, consensus, snapshot,
                         state_machine (the app seam), node (the engine). Transport-
                         and app-agnostic. Never depends on a higher layer.
include/hyle/services/   layer 2 (lib: hyle_services): the node minus the deployment shell.
                         Modules: kv/ (state, ops, kv_state_machine, ledger, pow); the
                         economy app (app, ops, schema, config, genesis); node machinery
                         (mempool, runtime, transport seam); util (keys, keyring, hex).
                         Depends on core.
include/hyle/morphe/     layer 3 (lib: hyle_morphe): the shell. The TCP transport (AsioMesh
                         + frame wire), the RPC/REST surfaces, the testnet generator, and
                         the morphe/techne executables. Depends on services.
src/{core,services,services/kv,morphe,techne}/   matching sources
tests/                   hyletests / embedtests / morphetests / e2etests, filter by suite
docs/                    APPLICATION, TRANSPORT (the public seams); COMETBFT_MAPPING,
                         CORNER_CASES (coverage)
```

An include is `<hyle/core/node.h>` or `<hyle/services/kv/state.h>`. Lower layers never include from a higher one. (The economy keeps the `hyle::morphe` namespace even though it lives in services, to be tidied later.)

## Coding practices

- Always build and test through `./build.sh` (`--test` runs every test executable; `--<exe> [suite]` runs one, e.g. `--hyletests ConsensusTests`); redirect output to a file, then grep/tail it.
- Use `hyle::wire` for serialization; do not hand-roll byte-shift loops.
- `xxx.h` maps to `src/xxx.cpp` under the same name.
- Comments and authored text: terse, factual, plain ASCII, no em-dashes, no narration, no design history. Reference what the code does today.
- Markdown is not hard-wrapped: one line per paragraph and per list item.
- This repo is public. No personal or local specifics (IPs, home paths, "do not commit" notes) in committed files.
