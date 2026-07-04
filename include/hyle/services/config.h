#ifndef HYLE_MORPHE_CONFIG_H
#define HYLE_MORPHE_CONFIG_H

#include <hyle/core/crypto.h>

#include <algorithm>
#include <cstdint>

namespace hyle::morphe {

struct Config {
  uint64_t fee_mint = 1;
  uint64_t fee_transfer = 1;
  uint64_t fee_entry = 1;

  uint64_t rent_rate = 0;
  uint64_t rip_bounty = 10;

  uint64_t pbts_window_secs = 3600;

  uint64_t reward_base = 2;
  unsigned reward_max_diff = 40;

  uint64_t mint_capacity = 4096;
  Hash mint_genesis_key{};
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

} // namespace hyle::morphe

#endif
