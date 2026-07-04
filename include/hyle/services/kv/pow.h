#ifndef HYLE_KV_POW_H
#define HYLE_KV_POW_H

#include <hyle/core/crypto.h>

#include <cstdint>

namespace hyle {

struct PowVerifier {
  virtual ~PowVerifier() = default;
  virtual Hash hash(const Hash& epoch_key, const PubKey& beneficiary, uint64_t nonce) const = 0;
};

// sha256(POW_TAG || epoch_key || beneficiary || nonce_be).
struct Sha256PowVerifier : PowVerifier {
  Hash hash(const Hash& epoch_key, const PubKey& beneficiary, uint64_t nonce) const override;
};

unsigned pow_difficulty(const Hash& h);

} // namespace hyle

#endif
