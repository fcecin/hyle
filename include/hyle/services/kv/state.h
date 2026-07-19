#ifndef HYLE_STATE_H
#define HYLE_STATE_H

#include <hyle/core/crypto.h>
#include <hyle/services/kv/ops.h>
#include <hyle/core/wire.h>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>

#include <cstdint>
#include <vector>

namespace hyle::services::kv {

class State {
public:
  void apply(const Op& op);
  void apply(const std::vector<Op>& ops);

  // The pointer is valid until the next mutation.
  const wire::Bytes* get(wire::View key) const;

  size_t size() const { return kv_.size(); }
  bool empty() const { return kv_.empty(); }
  // Total bytes held: sum of key+value sizes over all cells. Maintained on apply, recomputed on
  // restore. The economy caps total state against this (max_state_bytes).
  size_t bytes() const { return bytes_; }

  // [u32 count] then per entry [bytes key][bytes val], keys ascending.
  wire::Bytes canonical() const;

  void restore(wire::View canonical);

  Hash app_hash() const;

private:
  boost::unordered_flat_map<wire::Bytes, wire::Bytes, boost::hash<wire::Bytes>> kv_;
  size_t bytes_ = 0;
};

} // namespace hyle::services::kv

#endif
