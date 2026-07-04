#include <hyle/morphe/client_rest.h>

#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/json.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hyle::morphe {

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace json = boost::json;
using tcp = net::ip::tcp;

namespace {

std::vector<std::string> path_segments(std::string target) {
  const auto q = target.find('?');
  if (q != std::string::npos) target.resize(q);
  std::vector<std::string> out;
  std::string cur;
  for (char c : target) {
    if (c == '/') { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
    else cur.push_back(c);
  }
  if (!cur.empty()) out.push_back(cur);
  return out;
}

bool route(http::verb verb, const std::vector<std::string>& seg, const std::string& body,
           std::string& method, json::object& params) {
  if (verb == http::verb::post && seg.size() == 1 && seg[0] == "tx") {
    method = "submit_tx";
    params["tx"] = body;
    return true;
  }
  if (verb != http::verb::get) return false;
  if (seg.size() == 1) {
    if (seg[0] == "height") { method = "query.height"; return true; }
    return false;
  }
  if (seg.size() == 2) {
    if (seg[0] == "balance") { method = "query.balance"; params["pubkey"] = seg[1]; return true; }
    if (seg[0] == "account") { method = "query.account"; params["pubkey"] = seg[1]; return true; }
    if (seg[0] == "entry") { method = "query.entry"; params["name"] = seg[1]; return true; }
    if (seg[0] == "tx") { method = "query.tx"; params["tx_id"] = seg[1]; return true; }
    return false;
  }
  return false;
}

class RestSession : public std::enable_shared_from_this<RestSession> {
public:
  RestSession(tcp::socket&& sock, RpcService& svc, std::chrono::milliseconds idle)
      : stream_(std::move(sock)), svc_(svc), idle_(idle) {}
  void run() { do_read(); }

private:
  void do_read() {
    parser_.emplace();
    parser_->body_limit(64 * 1024);
    stream_.expires_after(idle_);
    http::async_read(stream_, buffer_, *parser_,
                     [self = shared_from_this()](beast::error_code ec, std::size_t) {
                       if (ec) return;
                       self->req_ = self->parser_->release();
                       self->on_read();
                     });
  }
  void reply(http::status st, const std::string& body) {
    auto res = std::make_shared<http::response<http::string_body>>(st, req_.version());
    res->set(http::field::content_type, "application/json");
    res->keep_alive(false);
    res->body() = body;
    res->prepare_payload();
    stream_.expires_after(idle_);
    http::async_write(stream_, *res, [self = shared_from_this(), res](beast::error_code, std::size_t) {
      beast::error_code ec;
      beast::get_lowest_layer(self->stream_).socket().shutdown(tcp::socket::shutdown_send, ec);
    });
  }
  void on_read() {
    if (req_.method() == http::verb::get && req_.target() == "/health") {
      const bool ready = svc_.runtime().height() > 0;
      reply(ready ? http::status::ok : http::status::service_unavailable,
            std::string("{\"live\":true,\"ready\":") + (ready ? "true" : "false") + "}");
      return;
    }
    std::string method;
    json::object params;
    const auto seg = path_segments(std::string(req_.target()));
    if (!route(req_.method(), seg, req_.body(), method, params)) {
      reply(http::status::not_found, R"({"error":{"code":404,"message":"no such route"}})");
      return;
    }
    try {
      json::value result = svc_.handle(method, params);
      reply(http::status::ok, json::serialize(result));
    } catch (const RpcError& e) {
      json::object err{{"error", json::object{{"code", e.code}, {"message", e.message}}}};
      reply(http::status::bad_request, json::serialize(err));
    } catch (const std::exception&) {
      // A non-RpcError escape must not leak e.what() on the public port.
      reply(http::status::internal_server_error,
            R"({"error":{"code":-32603,"message":"internal error"}})");
    }
  }

  beast::tcp_stream stream_;
  beast::flat_buffer buffer_;
  std::optional<http::request_parser<http::string_body>> parser_;
  http::request<http::string_body> req_;
  RpcService& svc_;
  std::chrono::milliseconds idle_;
};

}  // namespace

ClientRestServer::ClientRestServer(net::io_context& io, RpcService& svc, uint16_t port,
                                   const std::string& bind_addr, std::chrono::milliseconds idle_timeout)
    : io_(io), svc_(svc), acceptor_(io, tcp::endpoint(net::ip::make_address(bind_addr), port)),
      accept_timer_(io), idle_timeout_(idle_timeout) {}

uint16_t ClientRestServer::port() const { return acceptor_.local_endpoint().port(); }

void ClientRestServer::start() { do_accept(); }

void ClientRestServer::do_accept() {
  acceptor_.async_accept([this](beast::error_code ec, tcp::socket sock) {
    if (ec) {
      if (!acceptor_.is_open()) return;
      accept_timer_.expires_after(std::chrono::milliseconds(50));
      accept_timer_.async_wait([this](beast::error_code tec) { if (!tec) do_accept(); });
      return;
    }
    std::make_shared<RestSession>(std::move(sock), svc_, idle_timeout_)->run();
    do_accept();
  });
}

} // namespace hyle::morphe
