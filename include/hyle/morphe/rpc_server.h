#ifndef HYLE_MORPHE_RPC_SERVER_H
#define HYLE_MORPHE_RPC_SERVER_H

#include <hyle/morphe/rpc.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/json.hpp>

#include <cstdint>
#include <memory>
#include <set>
#include <string>

namespace hyle::morphe {
using namespace hyle::services;

class WsSession;

class RpcHttpServer {
public:
  RpcHttpServer(boost::asio::io_context& io, RpcService& svc, uint16_t port,
                const std::string& bind_addr = "127.0.0.1");

  uint16_t port() const;
  void start();
  void attach_events();

  // Call on the io thread.
  void publish(const std::string& topic, const boost::json::value& event);

  std::string metrics_text();

private:
  void do_accept();

  boost::asio::io_context& io_;
  RpcService& svc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::steady_timer accept_timer_;
  std::set<std::shared_ptr<WsSession>> subscribers_;
  friend class WsSession;
  friend class HttpSession;
};

} // namespace hyle::morphe

#endif
