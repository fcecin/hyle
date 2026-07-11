#ifndef HYLE_MORPHE_ASIO_MESH_H
#define HYLE_MORPHE_ASIO_MESH_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>
#include <hyle/morphe/frame.h>
#include <hyle/services/transport.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>

namespace hyle::morphe {
using namespace hyle::services;

class AsioMesh : public Transport {
public:
  AsioMesh(boost::asio::io_context& io, const KeyPair& key, uint32_t chain_tag, uint16_t listen_port,
           std::chrono::milliseconds handshake_deadline = std::chrono::seconds(10));

  uint16_t port() const;

  void add_peer(const PubKey& pk, const std::string& host, uint16_t port);

  void start();

  void send(const PubKey& dest, MsgType type, Channel ch, wire::View payload) override;
  void broadcast(MsgType type, Channel ch, wire::View payload) override;

  size_t connected() const;
  size_t peer_count() const override { return connected(); }

private:
  struct Session : std::enable_shared_from_this<Session> {
    boost::asio::ip::tcp::socket sock;
    PubKey peer{};
    bool identified = false;
    std::array<uint8_t, 32> challenge{};
    bool sent_auth = false;
    PubKey expect{};                   // dialer: the identity we dialed
    bool have_expect = false;
    std::vector<uint8_t> frame;
    std::deque<wire::Bytes> wq;
    bool writing = false;
    boost::asio::steady_timer deadline;
    bool pending = false;
    explicit Session(boost::asio::io_context& io) : sock(io), deadline(io) {}
  };
  using SessionPtr = std::shared_ptr<Session>;
  using tcp = boost::asio::ip::tcp;

  void do_accept();
  void dial(const PubKey& pk, const std::string& host, uint16_t peer_port);
  void maintain();
  void begin_session(SessionPtr s);
  void end_pending(const SessionPtr& s);
  void on_hello(SessionPtr s, const FrameHeader& h, wire::View payload);
  void on_hello_auth(SessionPtr s, const FrameHeader& h, wire::View payload);
  void read_header(SessionPtr s);
  void read_payload(SessionPtr s, uint32_t payload_len);
  void on_frame(SessionPtr s, const FrameHeader& h, wire::View payload);
  void enqueue(SessionPtr s, wire::Bytes bytes);
  void do_write(SessionPtr s);
  void drop_session(const SessionPtr& s);
  wire::Bytes frame_bytes(const PubKey& dest, MsgType type, Channel ch, wire::View payload,
                          uint8_t flags, uint8_t hop_count) const;

  boost::asio::io_context& io_;
  KeyPair key_;
  PubKey self_;
  uint32_t chain_tag_;
  tcp::acceptor acceptor_;
  std::map<PubKey, std::pair<std::string, uint16_t>> peers_;
  std::map<PubKey, SessionPtr> sessions_;
  std::set<PubKey> dialing_;
  boost::asio::steady_timer reconnect_timer_;
  boost::asio::steady_timer accept_timer_;
  std::chrono::milliseconds handshake_deadline_;
  size_t pending_count_ = 0;
  SeenCache seen_;

  static constexpr size_t kMaxPending = 256;
};

} // namespace hyle::morphe

#endif
