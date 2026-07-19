#ifndef HYLE_SERVICES_CONFIG_H
#define HYLE_SERVICES_CONFIG_H

#include <cstdint>

namespace hyle::services {

struct Config {
  uint64_t fee_transfer = 1;
  uint64_t fee_entry = 1;
  uint64_t fee_sudo = 1;

  uint64_t rent_rate = 0;
  uint64_t rip_bounty = 10;

  // A pending sudo proposal older than this cannot execute and is reaped on next touch.
  // 0 = never (fine for a solo chain, whose proposals execute in the block that opens them).
  uint64_t sudo_ttl_secs = 0;

  uint64_t pbts_window_secs = 3600;

  // Consensus rules, not economy: the validator-set bounds that gate governance votes, and the
  // max block payload that gates block acceptance. All nodes must agree, so they live here (in
  // the hashed genesis), never in per-node config -- a disagreement forks the chain.
  unsigned member_cap = 21;
  unsigned member_floor = 1;
  uint64_t max_value_bytes = 4u << 20;

  // Hard ceiling on total state RAM in bytes (sum of key+value over every cell). 0 = unbounded.
  // A consensus rule: when the store is at or over this, an op that would create a NEW cell (a new
  // entry or a new account) is rejected, so all nodes agree on which ops fail. Existing cells can
  // still be updated and funded, and rip frees space.
  uint64_t max_state_bytes = 0;

  // Per-block credit autofill over the validator set:
  // lift = credit_autofill_ceiling - max(validator balances); each validator
  // balance = min(ceiling, balance + lift + refill_rate). 0 ceiling disables.
  uint64_t credit_autofill_ceiling = 0;
  uint64_t refill_rate = 0;
};

} // namespace hyle::services

#endif
