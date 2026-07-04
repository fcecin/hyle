#ifndef HYLE_WIRE_H
#define HYLE_WIRE_H

// Big-endian; byte strings and lists carry a u32 length/count prefix.

#include <boost/endian/conversion.hpp>

#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace hyle::wire {

using Bytes = std::vector<uint8_t>;
using View = std::span<const uint8_t>;

struct Error : std::runtime_error {
  using std::runtime_error::runtime_error;
};

class Writer {
public:
  explicit Writer(Bytes& out) : out_(out) {}

  void u8(uint8_t v) { out_.push_back(v); }
  void u16(uint16_t v) { put_be(v); }
  void u32(uint32_t v) { put_be(v); }
  void u64(uint64_t v) { put_be(v); }

  // no length prefix
  void raw(View b) { out_.insert(out_.end(), b.begin(), b.end()); }

  void str(std::string_view s) { raw(View(reinterpret_cast<const uint8_t*>(s.data()), s.size())); }

  // u32 length prefix + bytes
  void bytes(View b) {
    if (b.size() > 0xffffffffull) throw Error("wire: bytes too long");
    u32(static_cast<uint32_t>(b.size()));
    raw(b);
  }

  // u32 count prefix
  void count(size_t n) {
    if (n > 0xffffffffull) throw Error("wire: count too large");
    u32(static_cast<uint32_t>(n));
  }

private:
  template <class T> void put_be(T v) {
    T be = boost::endian::native_to_big(v);
    uint8_t buf[sizeof(T)];
    std::memcpy(buf, &be, sizeof(T));
    out_.insert(out_.end(), buf, buf + sizeof(T));
  }
  Bytes& out_;
};

// raw()/bytes() views borrow the input span.
class Reader {
public:
  explicit Reader(View in) : in_(in) {}

  uint8_t u8() {
    need(1);
    return in_[pos_++];
  }
  uint16_t u16() { return get_be<uint16_t>(); }
  uint32_t u32() { return get_be<uint32_t>(); }
  uint64_t u64() { return get_be<uint64_t>(); }

  View raw(size_t n) {
    need(n);
    View v = in_.subspan(pos_, n);
    pos_ += n;
    return v;
  }

  View bytes() {
    uint32_t n = u32();
    return raw(n);
  }

  size_t count() {
    uint32_t n = u32();
    if (n > remaining()) throw Error("wire: count exceeds remaining bytes");
    return n;
  }

  size_t remaining() const { return in_.size() - pos_; }
  bool empty() const { return remaining() == 0; }

private:
  void need(size_t n) const {
    // compare against remaining, not pos_+n, which could wrap past SIZE_MAX
    if (n > in_.size() - pos_) throw Error("wire: short read");
  }
  template <class T> T get_be() {
    need(sizeof(T));
    T be;
    std::memcpy(&be, in_.data() + pos_, sizeof(T));
    pos_ += sizeof(T);
    return boost::endian::big_to_native(be);
  }
  View in_;
  size_t pos_ = 0;
};

} // namespace hyle::wire

#endif
