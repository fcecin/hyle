#ifndef HYLE_OPS_H
#define HYLE_OPS_H

#include <hyle/core/wire.h>

#include <cstdint>
#include <vector>

namespace hyle {

enum class OpKind : uint8_t {
  Put = 1,
  Del = 2,
};

struct Op {
  OpKind kind = OpKind::Put;
  wire::Bytes key;
  wire::Bytes val;

  static Op put(wire::View k, wire::View v) {
    return Op{OpKind::Put, wire::Bytes(k.begin(), k.end()), wire::Bytes(v.begin(), v.end())};
  }
  static Op del(wire::View k) {
    return Op{OpKind::Del, wire::Bytes(k.begin(), k.end()), {}};
  }

  bool operator==(const Op&) const = default;
};

// Wire: [u32 count] then per op [u8 kind][bytes key], plus [bytes val] for Put.
wire::Bytes encode_ops(const std::vector<Op>& ops);
std::vector<Op> decode_ops(wire::View in);

} // namespace hyle

#endif
