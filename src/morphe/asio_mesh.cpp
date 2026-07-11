#include <hyle/morphe/asio_mesh.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include <cryptopp/osrng.h>

#include <chrono>

namespace hyle::morphe {
using namespace hyle::services;

namespace asio = boost::asio;
using tcp = boost::asio::ip::tcp;

static constexpr uint32_t MAX_PAYLOAD = 16u << 20;
static constexpr uint8_t MAX_HOP = 2;
static constexpr size_t kMaxQueued = 8192;

static wire::Bytes hello_sign_bytes(uint32_t chain_tag, const PubKey& pub,
                                    const std::array<uint8_t, 32>& challenge) {
  wire::Bytes out;
  wire::Writer w(out);
  w.str("MORPHE_HELLO_V1");
  w.u32(chain_tag);
  w.raw(wire::View(pub.data(), pub.size()));
  w.raw(wire::View(challenge.data(), challenge.size()));
  return out;
}
static void fill_random(uint8_t* p, size_t n) {
  static CryptoPP::AutoSeededRandomPool rng;
  rng.GenerateBlock(p, n);
}

AsioMesh::AsioMesh(asio::io_context& io, const KeyPair& key, uint32_t chain_tag, uint16_t listen_port,
                   std::chrono::milliseconds handshake_deadline)
    : io_(io), key_(key), self_(key.pub), chain_tag_(chain_tag),
      acceptor_(io, tcp::endpoint(tcp::v4(), listen_port)), reconnect_timer_(io), accept_timer_(io),
      handshake_deadline_(handshake_deadline) {}

uint16_t AsioMesh::port() const { return acceptor_.local_endpoint().port(); }

void AsioMesh::add_peer(const PubKey& pk, const std::string& host, uint16_t peer_port) {
  peers_[pk] = {host, peer_port};
}

size_t AsioMesh::connected() const {
  size_t c = 0;
  for (const auto& kv : sessions_)
    if (kv.second->identified) ++c;
  return c;
}

void AsioMesh::start() {
  do_accept();
  maintain();
}

void AsioMesh::maintain() {
  for (const auto& kv : peers_) {
    const PubKey& pk = kv.first;
    if (!(self_ < pk)) continue;  // the other side dials this pair
    auto it = sessions_.find(pk);
    const bool connected = it != sessions_.end() && it->second->identified;
    if (connected || dialing_.count(pk)) continue;
    dial(pk, kv.second.first, kv.second.second);
  }
  reconnect_timer_.expires_after(std::chrono::milliseconds(500));
  reconnect_timer_.async_wait([this](const boost::system::error_code& ec) {
    if (!ec) maintain();
  });
}

void AsioMesh::do_accept() {
  auto s = std::make_shared<Session>(io_);
  acceptor_.async_accept(s->sock, [this, s](const boost::system::error_code& ec) {
    if (ec) {
      accept_timer_.expires_after(std::chrono::milliseconds(50));
      accept_timer_.async_wait([this](const boost::system::error_code& tec) { if (!tec) do_accept(); });
      return;
    }
    if (pending_count_ >= kMaxPending) {
      boost::system::error_code cec;
      s->sock.close(cec);
    } else {
      s->pending = true;
      ++pending_count_;
      begin_session(s);
    }
    do_accept();
  });
}

void AsioMesh::end_pending(const SessionPtr& s) {
  if (s->pending) { s->pending = false; if (pending_count_) --pending_count_; }
}

void AsioMesh::dial(const PubKey& pk, const std::string& host, uint16_t peer_port) {
  auto s = std::make_shared<Session>(io_);
  tcp::endpoint ep(asio::ip::make_address(host), peer_port);
  dialing_.insert(pk);
  s->expect = pk;
  s->have_expect = true;
  s->sock.async_connect(ep, [this, s, pk](const boost::system::error_code& ec) {
    if (ec) { dialing_.erase(pk); return; }
    begin_session(s);
  });
}

void AsioMesh::begin_session(SessionPtr s) {
  s->deadline.expires_after(handshake_deadline_);
  s->deadline.async_wait([this, s](const boost::system::error_code& ec) {
    if (ec || s->identified) return;
    boost::system::error_code cec;
    s->sock.close(cec);
    drop_session(s);
  });
  fill_random(s->challenge.data(), s->challenge.size());
  enqueue(s, frame_bytes(PubKey{}, MsgType::Hello, Channel::Consensus,
                         wire::View(s->challenge.data(), s->challenge.size()), 0, 0));
  read_header(s);
}

void AsioMesh::read_header(SessionPtr s) {
  s->frame.assign(FRAME_HEADER_SIZE, 0);
  asio::async_read(s->sock, asio::buffer(s->frame.data(), FRAME_HEADER_SIZE),
                   [this, s](const boost::system::error_code& ec, std::size_t) {
                     if (ec) { drop_session(s); return; }
                     const uint8_t* p = s->frame.data() + FRAME_HEADER_SIZE - 4;  // payload_len
                     uint32_t plen = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                                     (uint32_t(p[2]) << 8) | uint32_t(p[3]);
                     if (plen > MAX_PAYLOAD) { drop_session(s); return; }
                     read_payload(s, plen);
                   });
}

void AsioMesh::read_payload(SessionPtr s, uint32_t plen) {
  s->frame.resize(FRAME_HEADER_SIZE + plen);
  asio::async_read(s->sock, asio::buffer(s->frame.data() + FRAME_HEADER_SIZE, plen),
                   [this, s](const boost::system::error_code& ec, std::size_t) {
                     if (ec) { drop_session(s); return; }
                     try {
                       FrameHeader h;
                       wire::View payload = decode_frame(wire::View(s->frame.data(), s->frame.size()), h);
                       on_frame(s, h, payload);
                     } catch (const wire::Error&) {
                       drop_session(s);
                       return;
                     }
                     read_header(s);
                   });
}

void AsioMesh::drop_session(const SessionPtr& s) {
  end_pending(s);
  if (s->have_expect) dialing_.erase(s->expect);
  if (!s->identified) return;
  auto it = sessions_.find(s->peer);
  if (it != sessions_.end() && it->second == s) sessions_.erase(it);
}

void AsioMesh::on_hello(SessionPtr s, const FrameHeader& h, wire::View payload) {
  if (s->sent_auth || payload.size() != 32) return;
  std::array<uint8_t, 32> peer_challenge{};
  std::copy(payload.begin(), payload.end(), peer_challenge.begin());
  const wire::Bytes sb = hello_sign_bytes(chain_tag_, self_, peer_challenge);
  const Sig sig = key_.sign(wire::View(sb.data(), sb.size()));
  enqueue(s, frame_bytes(h.src, MsgType::HelloAuth, Channel::Consensus,
                         wire::View(sig.data(), sig.size()), 0, 0));
  s->sent_auth = true;
}

void AsioMesh::on_hello_auth(SessionPtr s, const FrameHeader& h, wire::View payload) {
  boost::system::error_code ec;
  if (s->identified || payload.size() != 64) return;
  Sig sig{};
  std::copy(payload.begin(), payload.end(), sig.begin());
  const wire::Bytes sb = hello_sign_bytes(chain_tag_, h.src, s->challenge);
  if (!verify(h.src, wire::View(sb.data(), sb.size()), sig)) { s->sock.close(ec); return; }
  if (s->have_expect) { if (!(h.src == s->expect)) { s->sock.close(ec); return; } }
  else if (peers_.find(h.src) == peers_.end()) { s->sock.close(ec); return; }
  auto exi = sessions_.find(h.src);
  if (exi != sessions_.end() && exi->second->identified && exi->second != s) { s->sock.close(ec); return; }
  s->peer = h.src;
  s->identified = true;
  s->deadline.cancel();
  end_pending(s);
  sessions_[h.src] = s;
  dialing_.erase(h.src);
}

void AsioMesh::on_frame(SessionPtr s, const FrameHeader& h, wire::View payload) {
  if (h.chain_tag != chain_tag_) return;
  if (!s->identified) {
    if (h.type == MsgType::Hello) on_hello(s, h, payload);
    else if (h.type == MsgType::HelloAuth) on_hello_auth(s, h, payload);
    return;
  }
  if (h.type == MsgType::Hello || h.type == MsgType::HelloAuth) return;

  if (!(h.flags & FLAG_FORWARD) && !(h.src == s->peer)) return;

  // Deliver-once: dedup every payload frame.
  if (!seen_.insert(h.msg_id)) return;

  if (h.dest == self_) {
    if (on_recv) on_recv(h.src, h.type, payload);
    return;
  }
  if (h.hop_count >= MAX_HOP) return;
  auto it = sessions_.find(h.dest);
  if (it == sessions_.end() || !it->second->identified) return;
  FrameHeader fwd = h;
  fwd.hop_count = static_cast<uint8_t>(h.hop_count + 1);
  fwd.flags |= FLAG_FORWARD;
  enqueue(it->second, encode_frame(fwd, payload));
}

wire::Bytes AsioMesh::frame_bytes(const PubKey& dest, MsgType type, Channel ch, wire::View payload,
                                  uint8_t flags, uint8_t hop_count) const {
  FrameHeader h;
  h.version = PROTOCOL_VERSION;
  h.chain_tag = chain_tag_;
  h.type = type;
  h.channel = static_cast<uint8_t>(ch);
  h.hop_count = hop_count;
  h.flags = flags;
  h.dest = dest;
  h.src = self_;
  h.msg_id = make_msg_id(self_, dest, payload);
  return encode_frame(h, payload);
}

void AsioMesh::send(const PubKey& dest, MsgType type, Channel ch, wire::View payload) {
  auto it = sessions_.find(dest);
  if (it != sessions_.end() && it->second->identified) {
    enqueue(it->second, frame_bytes(dest, type, ch, payload, 0, 0));
    return;
  }
  for (const auto& kv : sessions_) {
    if (kv.first == dest || !kv.second->identified) continue;
    enqueue(kv.second, frame_bytes(dest, type, ch, payload, FLAG_FORWARD, 0));
    return;
  }
}

void AsioMesh::broadcast(MsgType type, Channel ch, wire::View payload) {
  for (const auto& kv : peers_) send(kv.first, type, ch, payload);
}

void AsioMesh::enqueue(SessionPtr s, wire::Bytes bytes) {
  if (s->wq.size() >= kMaxQueued) {
    boost::system::error_code ec;
    s->sock.close(ec);
    drop_session(s);
    return;
  }
  s->wq.push_back(std::move(bytes));
  if (!s->writing) do_write(s);
}

void AsioMesh::do_write(SessionPtr s) {
  s->writing = true;
  asio::async_write(s->sock, asio::buffer(s->wq.front()),
                    [this, s](const boost::system::error_code& ec, std::size_t) {
                      if (ec) { s->writing = false; drop_session(s); return; }
                      s->wq.pop_front();
                      if (s->wq.empty()) s->writing = false;
                      else do_write(s);
                    });
}

} // namespace hyle::morphe
