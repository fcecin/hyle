#ifndef HYLE_MORPHE_FRAME_H
#define HYLE_MORPHE_FRAME_H

// Every message is [98-byte header][payload], big-endian.

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>
#include <hyle/services/transport.h>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_set.hpp>

#include <array>
#include <cstdint>
#include <deque>

namespace hyle::morphe {

inline constexpr uint8_t MSG_TYPE_MAX = static_cast<uint8_t>(MsgType::HelloAuth);

inline constexpr uint32_t FRAME_MAGIC = 0x4D50484D;  // "MPHM"
inline constexpr uint16_t PROTOCOL_VERSION = 1;
inline constexpr size_t FRAME_HEADER_SIZE = 98;
inline constexpr uint8_t FLAG_FORWARD = 0x01;

using MsgId = std::array<uint8_t, 16>;

struct FrameHeader {
  uint16_t version = PROTOCOL_VERSION;
  uint32_t chain_tag = 0;
  MsgType type = MsgType::Ping;
  uint8_t channel = 0;
  uint8_t hop_count = 0;
  uint8_t flags = 0;  // bit0 = FORWARD
  PubKey dest{};
  PubKey src{};
  MsgId msg_id{};
  uint32_t payload_len = 0;
};

uint32_t chain_tag_of(wire::View chain_id);            // first 4 bytes of sha256(chain_id)
// First 16 bytes of sha256(src || dest || payload).
MsgId make_msg_id(const PubKey& src, const PubKey& dest, wire::View payload);

wire::Bytes encode_frame(const FrameHeader& h, wire::View payload);
wire::View decode_frame(wire::View in, FrameHeader& out_header);

class SeenCache {
public:
  explicit SeenCache(size_t capacity = 8192) : cap_(capacity) {}
  bool insert(const MsgId& id);  // true if new; false if already seen
  size_t size() const { return set_.size(); }

private:
  size_t cap_;
  boost::unordered_flat_set<MsgId, boost::hash<MsgId>> set_;
  std::deque<MsgId> order_;
};

} // namespace hyle::morphe

#endif
