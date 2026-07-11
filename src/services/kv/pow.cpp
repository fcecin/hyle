#include <hyle/services/kv/pow.h>

#include <hyle/core/wire.h>

#include <cstring>

namespace hyle::services::kv {

Hash Sha256PowVerifier::hash(const Hash& epoch_key, const PubKey& beneficiary,
                             uint64_t nonce) const {
  wire::Bytes buf;
  wire::Writer w(buf);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>("HYLE_POW_V1"), 11));
  w.raw(wire::View(epoch_key.data(), epoch_key.size()));
  w.raw(wire::View(beneficiary.data(), beneficiary.size()));
  w.u64(nonce);
  return sha256(wire::View(buf));
}

unsigned pow_difficulty(const Hash& h) {
  unsigned bits = 0;
  for (uint8_t b : h) {
    if (b == 0) {
      bits += 8;
      continue;
    }
    for (int i = 7; i >= 0; --i) {
      if (b & (1u << i)) return bits;
      ++bits;
    }
    return bits;
  }
  return bits;
}

} // namespace hyle::services::kv
