#ifndef HYLE_SERVICES_CONFIG_H
#define HYLE_SERVICES_CONFIG_H

#include <hyle/core/crypto.h>

#include <algorithm>
#include <cstdint>

namespace hyle::services {

struct Config {
  uint64_t fee_mint = 1;
  uint64_t fee_transfer = 1;
  uint64_t fee_entry = 1;
  uint64_t fee_sudo = 1;

  uint64_t rent_rate = 0;
  uint64_t rip_bounty = 10;

  // A pending sudo proposal older than this cannot execute and is reaped on next touch.
  // 0 = never (fine for a solo chain, whose proposals execute in the block that opens them).
  uint64_t sudo_ttl_secs = 0;

  uint64_t pbts_window_secs = 3600;

  uint64_t reward_base = 2;
  unsigned reward_max_diff = 40;

  uint64_t mint_capacity = 4096;
  Hash mint_genesis_key{};

  // Consensus rules, not economy: the validator-set bounds that gate governance votes, and the
  // max block payload that gates block acceptance. All nodes must agree, so they live here (in
  // the hashed genesis), never in per-node config -- a disagreement forks the chain.
  unsigned member_cap = 21;
  unsigned member_floor = 1;
  uint64_t max_value_bytes = 4u << 20;

  // Per-block credit autofill over the validator set:
  // lift = credit_autofill_ceiling - max(validator balances); each validator
  // balance = min(ceiling, balance + lift + refill_rate). 0 ceiling disables.
  uint64_t credit_autofill_ceiling = 0;
  uint64_t refill_rate = 0;
};

inline uint64_t reward_for(const Config& cfg, unsigned difficulty) {
  if (difficulty == 0) return 0;
  unsigned d = std::min(difficulty, cfg.reward_max_diff);
  uint64_t r = cfg.reward_base;
  for (unsigned i = 1; i < d; ++i) {
    if (r > UINT64_MAX / 2) return UINT64_MAX;
    r *= 2;
  }
  return r;
}

} // namespace hyle::services

#endif
