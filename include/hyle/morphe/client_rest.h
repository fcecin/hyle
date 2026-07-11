#ifndef HYLE_MORPHE_CLIENT_REST_H
#define HYLE_MORPHE_CLIENT_REST_H

#include <hyle/morphe/rpc.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace hyle::morphe {
using namespace hyle::services;

class ClientRestServer {
public:
  ClientRestServer(boost::asio::io_context& io, RpcService& svc, uint16_t port,
                   const std::string& bind_addr = "0.0.0.0",
                   std::chrono::milliseconds idle_timeout = std::chrono::seconds(30));

  uint16_t port() const;
  void start();

private:
  void do_accept();

  boost::asio::io_context& io_;
  RpcService& svc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  boost::asio::steady_timer accept_timer_;
  std::chrono::milliseconds idle_timeout_;
};

} // namespace hyle::morphe

#endif
