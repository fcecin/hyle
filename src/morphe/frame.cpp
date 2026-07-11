#include <hyle/morphe/frame.h>

#include <cstring>

namespace hyle::morphe {
using namespace hyle::services;

uint32_t chain_tag_of(wire::View chain_id) {
  const Hash h = sha256(chain_id);
  return (static_cast<uint32_t>(h[0]) << 24) | (static_cast<uint32_t>(h[1]) << 16) |
         (static_cast<uint32_t>(h[2]) << 8) | static_cast<uint32_t>(h[3]);
}

MsgId make_msg_id(const PubKey& src, const PubKey& dest, wire::View payload) {
  wire::Bytes buf(src.begin(), src.end());
  buf.insert(buf.end(), dest.begin(), dest.end());
  buf.insert(buf.end(), payload.begin(), payload.end());
  const Hash h = sha256(wire::View(buf.data(), buf.size()));
  MsgId id{};
  std::memcpy(id.data(), h.data(), 16);
  return id;
}

wire::Bytes encode_frame(const FrameHeader& h, wire::View payload) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u32(FRAME_MAGIC);
  w.u16(h.version);
  w.u32(h.chain_tag);
  w.u8(static_cast<uint8_t>(h.type));
  w.u8(h.channel);
  w.u8(h.hop_count);
  w.u8(h.flags);
  w.raw(wire::View(h.dest.data(), h.dest.size()));
  w.raw(wire::View(h.src.data(), h.src.size()));
  w.raw(wire::View(h.msg_id.data(), h.msg_id.size()));
  if (payload.size() > 0xFFFFFFFFull)
    throw wire::Error("frame: payload too large");
  w.u32(static_cast<uint32_t>(payload.size()));
  w.raw(payload);
  return out;
}

wire::View decode_frame(wire::View in, FrameHeader& out) {
  wire::Reader r(in);
  if (r.u32() != FRAME_MAGIC) throw wire::Error("frame: bad magic");
  out.version = r.u16();
  out.chain_tag = r.u32();
  const uint8_t t = r.u8();
  if (t > MSG_TYPE_MAX) throw wire::Error("frame: unknown message type");
  out.type = static_cast<MsgType>(t);
  out.channel = r.u8();
  out.hop_count = r.u8();
  out.flags = r.u8();
  std::memcpy(out.dest.data(), r.raw(32).data(), 32);
  std::memcpy(out.src.data(), r.raw(32).data(), 32);
  std::memcpy(out.msg_id.data(), r.raw(16).data(), 16);
  out.payload_len = r.u32();
  const wire::View payload = r.raw(out.payload_len);
  if (!r.empty()) throw wire::Error("frame: trailing bytes after payload");
  return payload;
}

bool SeenCache::insert(const MsgId& id) {
  if (!set_.insert(id).second) return false;
  order_.push_back(id);
  while (order_.size() > cap_) {
    set_.erase(order_.front());
    order_.pop_front();
  }
  return true;
}

} // namespace hyle::morphe
