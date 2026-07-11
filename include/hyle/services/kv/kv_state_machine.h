#ifndef HYLE_KV_STATE_MACHINE_H
#define HYLE_KV_STATE_MACHINE_H

#include <hyle/services/kv/ops.h>
#include <hyle/services/kv/state.h>
#include <hyle/core/state_machine.h>
#include <hyle/core/wire.h>

#include <vector>

namespace hyle::services::kv {

class KvStateMachine : public StateMachine {
public:
  void submit(Op op) { pending_.push_back(std::move(op)); }

  wire::Bytes build_payload(uint64_t height) override;
  bool validate_payload(wire::View payload) override;
  void apply_payload(const ApplyContext& ctx, wire::View payload) override;
  wire::Bytes snapshot() const override { return state_.canonical(); }
  void restore(wire::View bytes) override;

  const State& state() const { return state_; }

private:
  State state_;
  std::vector<Op> pending_;
};

} // namespace hyle::services::kv

#endif
