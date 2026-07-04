#ifndef HYLE_STATE_H
#define HYLE_STATE_H

#include <hyle/core/crypto.h>
#include <hyle/services/kv/ops.h>
#include <hyle/core/wire.h>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>

#include <cstdint>
#include <vector>

namespace hyle {

class State {
public:
  void apply(const Op& op);
  void apply(const std::vector<Op>& ops);

  // The pointer is valid until the next mutation.
  const wire::Bytes* get(wire::View key) const;

  size_t size() const { return kv_.size(); }
  bool empty() const { return kv_.empty(); }

  // [u32 count] then per entry [bytes key][bytes val], keys ascending.
  wire::Bytes canonical() const;

  void restore(wire::View canonical);

  Hash app_hash() const;

private:
  boost::unordered_flat_map<wire::Bytes, wire::Bytes, boost::hash<wire::Bytes>> kv_;
};

} // namespace hyle

#endif
