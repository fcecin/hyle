#ifndef HYLE_SERVICES_TRANSPORT_H
#define HYLE_SERVICES_TRANSPORT_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <functional>

namespace hyle::morphe {

// Values are wire-stable.
enum class MsgType : uint8_t {
  Hello = 0,
  Ping = 1, Pong = 2, PeerMap = 3,
  Consensus = 4,
  Prop = 12,      // [u64 height][u64 round][proposer:32][value bytes][sig:64]
  HelloAuth = 13,
  ValueReq = 5, ValueResp = 6, SnapReq = 7, SnapResp = 8, Tx = 9, Inv = 10, Want = 11,
};

enum class Channel : uint8_t { Consensus = 0, Mempool = 1, Bulk = 2 };

struct Transport {
  virtual ~Transport() = default;

  virtual void send(const PubKey& dest, MsgType type, Channel ch, wire::View payload) = 0;
  virtual void broadcast(MsgType type, Channel ch, wire::View payload) = 0;

  virtual size_t peer_count() const { return 0; }

  // `payload` is valid only for the duration of the call.
  std::function<void(const PubKey& src, MsgType type, wire::View payload)> on_recv;
};

} // namespace hyle::morphe

#endif
