#ifndef HYLE_SNAPSHOT_H
#define HYLE_SNAPSHOT_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <malachite/engine.hpp>

#include <cstdint>
#include <vector>

namespace hyle {

struct Attestation {
  uint64_t height = 0;
  Hash app_hash{};
  PubKey signer{};
  Sig sig{};
};

wire::Bytes attestation_bytes(uint64_t height, const Hash& app_hash);

struct Snapshot {
  uint64_t height = 0;
  wire::Bytes governance;
  wire::Bytes app;
  malachite::ValidatorSet next_set;   // operative at height+1
  malachite::ValidatorSet next_set2;  // operative at height+2 (carries a change decided at this height)
  std::vector<Attestation> attestations;
};

// A snapshot travels as two halves so it scales to gigabyte state:
//
//   Checkpoint -- small, pooled. The proof-of-height a joiner trusts: app_hash at a height, the
//   +1/+2 validator sets, and attestations. Attestations are per-signer, so a joiner pools
//   checkpoints from many peers until >2/3 of a trusted set attest to one app_hash, then it trusts
//   that app_hash and those sets. Cheap to broadcast and merge.
//
//   State blob -- big, streamed. The governance and application bytes, moved whole over a bulk
//   transport lane (the transport owns all chunking/reassembly; the core never sees a chunk).
//   Integrity is the composite hash: a joiner recomputes hash(chain_id ++ gov ++ app) and checks
//   it equals the checkpoint's quorum-verified app_hash. A forged blob fails that and is dropped.
struct SnapshotCheckpoint {
  uint64_t height = 0;
  Hash app_hash{};
  malachite::ValidatorSet next_set;
  malachite::ValidatorSet next_set2;
  std::vector<Attestation> attestations;
};

// A key over a checkpoint's content minus its attestations, so checkpoints for the same (height,
// app_hash, sets) from different signers merge into one pooled candidate.
Hash checkpoint_content_key(const SnapshotCheckpoint& c);

// True if `trusted` has >2/3 voting power attesting the checkpoint's (height, app_hash), each
// signature verified, duplicates and unknown signers ignored. The weak-subjectivity gate.
bool checkpoint_has_quorum(const SnapshotCheckpoint& c, const malachite::ValidatorSet& trusted);

// decode_* throw wire::Error on malformed input.
wire::Bytes encode_checkpoint(const SnapshotCheckpoint& c);
SnapshotCheckpoint decode_checkpoint(wire::View v);

// [bytes governance][bytes app]. The big half; hash(chain_id ++ gov ++ app) must equal app_hash.
wire::Bytes encode_state_blob(wire::View governance, wire::View app);
struct StateBlob {
  wire::Bytes governance;
  wire::Bytes app;
};
StateBlob decode_state_blob(wire::View v);

} // namespace hyle

#endif
