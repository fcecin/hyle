#pragma once

#include <hyle/core/crypto.h>
#include <hyle/core/state_machine.h>
#include <hyle/core/wire.h>

#include <cstring>
#include <functional>
#include <vector>

struct MockStateMachine : hyle::StateMachine {
  std::function<hyle::wire::Bytes(uint64_t)> payload_fn;
  bool accept = true;
  std::vector<hyle::wire::Bytes> applied;
  hyle::Hash state{};

  hyle::wire::Bytes build_payload(uint64_t height) override {
    if (payload_fn) return payload_fn(height);
    hyle::wire::Bytes v;
    hyle::wire::Writer(v).u64(height);
    return v;
  }
  bool validate_payload(hyle::wire::View) override { return accept; }
  void apply_payload(const hyle::ApplyContext& ctx, hyle::wire::View payload) override {
    if (applied.size() < ctx.height) applied.resize(ctx.height);
    applied[ctx.height - 1].assign(payload.begin(), payload.end());
    hyle::wire::Bytes buf(state.begin(), state.end());
    buf.insert(buf.end(), payload.begin(), payload.end());
    state = hyle::sha256(hyle::wire::View(buf));
  }
  hyle::wire::Bytes snapshot() const override {
    return hyle::wire::Bytes(state.begin(), state.end());
  }
  void restore(hyle::wire::View bytes) override {
    state = hyle::Hash{};
    if (bytes.size() == state.size()) std::memcpy(state.data(), bytes.data(), state.size());
  }
};
