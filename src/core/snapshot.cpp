#include <hyle/core/snapshot.h>

namespace hyle {

// Do not drop chain_id from the composite hash without re-checking cross-chain replay.
wire::Bytes attestation_bytes(uint64_t height, const Hash& app_hash) {
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>("HYLE_APPHASH_V1"), 15));
  w.u64(height);
  w.raw(wire::View(app_hash.data(), app_hash.size()));
  return out;
}

} // namespace hyle
