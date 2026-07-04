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

} // namespace hyle

#endif
