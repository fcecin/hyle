#ifndef HYLE_STATE_MACHINE_H
#define HYLE_STATE_MACHINE_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <vector>

namespace hyle {

struct ApplyContext {
  uint64_t height = 0;
  PubKey proposer{};  // zero if the committed round's proposer was not observed
  // The active validator set at this height and 2/3+1 of it, so an app that runs its own
  // governance (sudo) can weigh votes without the base decoding the act.
  std::vector<PubKey> members;
  unsigned quorum = 0;
};

struct StateMachine {
  virtual ~StateMachine() = default;

  virtual wire::Bytes build_payload(uint64_t height) = 0;

  // Must not mutate state.
  virtual bool validate_payload(wire::View payload) = 0;

  virtual void apply_payload(const ApplyContext& ctx, wire::View payload) = 0;

  // Validators that left the active set at the applied height, so an app can reclaim
  // per-validator state. Part of the deterministic transition; every node runs it.
  virtual void on_validators_removed(const std::vector<PubKey>& /*removed*/) {}

  // Canonical serialization of the app's own state.
  virtual wire::Bytes snapshot() const = 0;

  // Must be atomic: on malformed/truncated bytes throw (wire::Error), leave state unchanged.
  virtual void restore(wire::View) = 0;
};

} // namespace hyle

#endif
