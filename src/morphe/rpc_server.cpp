#include <hyle/morphe/rpc_server.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <hyle/services/hex.h>

#include <chrono>
#include <deque>
#include <sstream>
#include <string>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace json = boost::json;
using tcp = net::ip::tcp;

namespace hyle::morphe {
using namespace hyle::services;

namespace {

std::string handle_jsonrpc(RpcService& svc, const std::string& body) {
  json::object resp{{"jsonrpc", "2.0"}};
  json::value id = nullptr;
  try {
    json::value v = json::parse(body);
    const json::object& o = v.as_object();
    if (o.contains("id")) id = o.at("id");
    resp["id"] = id;
    const std::string method(o.at("method").as_string().c_str());
    json::object params = (o.contains("params") && o.at("params").is_object())
                              ? o.at("params").as_object() : json::object{};
    try {
      resp["result"] = svc.handle(method, params);
    } catch (const RpcError& e) {
      resp["error"] = json::object{{"code", e.code}, {"message", e.message}};
    } catch (const std::exception&) {
      resp["error"] = json::object{{"code", -32603}, {"message", "internal error"}};
    }
  } catch (const std::exception&) {
    resp["id"] = id;
    resp["error"] = json::object{{"code", -32700}, {"message", "parse error"}};
  }
  return json::serialize(resp);
}

}  // namespace

class WsSession : public std::enable_shared_from_this<WsSession> {
public:
  std::string topic;

  WsSession(tcp::socket&& sock, RpcHttpServer* srv, RpcService& svc)
      : ws_(std::move(sock)), server_(srv), svc_(svc) {}

  void run(http::request<http::string_body> req) {
    ws_.async_accept(req, [self = shared_from_this()](beast::error_code ec) {
      if (!ec) self->do_read();
    });
  }

  void send(std::string s) {
    if (outq_.size() >= 8192) { unregister(); beast::get_lowest_layer(ws_).close(); return; }
    outq_.push_back(std::move(s));
    if (!writing_) do_write();
  }

private:
  void do_read() {
    ws_.async_read(buffer_, [self = shared_from_this()](beast::error_code ec, std::size_t) {
      if (ec) { self->unregister(); return; }
      self->on_read();
    });
  }
  void on_read() {
    std::string msg = beast::buffers_to_string(buffer_.data());
    buffer_.consume(buffer_.size());
    try {
      json::value v = json::parse(msg);
      const json::object& o = v.as_object();
      const std::string method(o.at("method").as_string().c_str());
      json::object params = (o.contains("params") && o.at("params").is_object())
                                ? o.at("params").as_object() : json::object{};
      if (method == "subscribe") {
        topic = std::string(params.at("topic").as_string().c_str());
        server_->subscribers_.insert(shared_from_this());
        send(json::serialize(json::object{{"subscribed", topic}}));
      } else {
        json::object resp{{"jsonrpc", "2.0"}};
        if (o.contains("id")) resp["id"] = o.at("id");
        try {
          resp["result"] = svc_.handle(method, params);
        } catch (const RpcError& e) {
          resp["error"] = json::object{{"code", e.code}, {"message", e.message}};
        }
        send(json::serialize(resp));
      }
    } catch (const std::exception&) {
    }
    do_read();
  }
  void do_write() {
    writing_ = true;
    ws_.text(true);
    ws_.async_write(net::buffer(outq_.front()),
                    [self = shared_from_this()](beast::error_code ec, std::size_t) {
                      if (ec) { self->unregister(); return; }
                      self->outq_.pop_front();
                      if (self->outq_.empty()) self->writing_ = false;
                      else self->do_write();
                    });
  }
  void unregister() {
    if (server_) server_->subscribers_.erase(shared_from_this());
  }

  websocket::stream<beast::tcp_stream> ws_;
  beast::flat_buffer buffer_;
  RpcHttpServer* server_;
  RpcService& svc_;
  std::deque<std::string> outq_;
  bool writing_ = false;
};

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
  HttpSession(tcp::socket&& sock, RpcHttpServer* srv, RpcService& svc)
      : stream_(std::move(sock)), server_(srv), svc_(svc) {}

  void run() { do_read(); }

private:
  void do_read() {
    req_ = {};
    stream_.expires_after(std::chrono::seconds(30));
    http::async_read(stream_, buffer_, req_,
                     [self = shared_from_this()](beast::error_code ec, std::size_t) {
                       if (ec) return;
                       self->on_read();
                     });
  }
  void on_read() {
    if (websocket::is_upgrade(req_)) {
      std::make_shared<WsSession>(stream_.release_socket(), server_, svc_)
          ->run(std::move(req_));
      return;
    }
    auto res = std::make_shared<http::response<http::string_body>>(http::status::ok, req_.version());
    res->keep_alive(false);
    if (req_.method() == http::verb::get && req_.target() == "/metrics") {
      res->set(http::field::content_type, "text/plain; version=0.0.4");
      res->body() = server_->metrics_text();
    } else if (req_.method() == http::verb::get && req_.target() == "/health") {
      const bool ready = svc_.runtime().height() > 0;
      res->result(ready ? http::status::ok : http::status::service_unavailable);
      res->set(http::field::content_type, "application/json");
      res->body() = std::string("{\"live\":true,\"ready\":") + (ready ? "true" : "false") + "}";
    } else {
      res->set(http::field::content_type, "application/json");
      res->body() = handle_jsonrpc(svc_, req_.body());
    }
    res->prepare_payload();
    stream_.expires_after(std::chrono::seconds(30));
    http::async_write(stream_, *res,
                      [self = shared_from_this(), res](beast::error_code, std::size_t) {
                        beast::error_code ec;
                        beast::get_lowest_layer(self->stream_).socket().shutdown(
                            tcp::socket::shutdown_send, ec);
                      });
  }

  beast::tcp_stream stream_;
  beast::flat_buffer buffer_;
  http::request<http::string_body> req_;
  RpcHttpServer* server_;
  RpcService& svc_;
};

namespace {
// This server exposes the unauthenticated control surface; its safety rests on being bound to loopback.
net::ip::address require_loopback(const std::string& s) {
  const auto a = net::ip::make_address(s);
  if (!a.is_loopback())
    throw std::runtime_error("control RPC refuses a non-loopback bind (" + s + "): it is the "
                             "UNAUTHENTICATED admin surface; firewall it and bind loopback");
  return a;
}
}  // namespace

RpcHttpServer::RpcHttpServer(net::io_context& io, RpcService& svc, uint16_t port,
                             const std::string& bind_addr)
    : io_(io), svc_(svc),
      acceptor_(io, tcp::endpoint(require_loopback(bind_addr), port)), accept_timer_(io) {}

uint16_t RpcHttpServer::port() const { return acceptor_.local_endpoint().port(); }

void RpcHttpServer::start() { do_accept(); }

void RpcHttpServer::do_accept() {
  acceptor_.async_accept([this](beast::error_code ec, tcp::socket sock) {
    if (ec) {
      if (!acceptor_.is_open()) return;
      accept_timer_.expires_after(std::chrono::milliseconds(50));
      accept_timer_.async_wait([this](beast::error_code tec) { if (!tec) do_accept(); });
      return;
    }
    std::make_shared<HttpSession>(std::move(sock), this, svc_)->run();
    do_accept();
  });
}

void RpcHttpServer::publish(const std::string& topic, const json::value& event) {
  const std::string s = json::serialize(json::object{{"topic", topic}, {"event", event}});
  // Copy the subscriber set first: send() can call unregister(), which would invalidate an iterator into
  // the live set mid-loop.
  const std::vector<std::shared_ptr<WsSession>> subs(subscribers_.begin(), subscribers_.end());
  for (const auto& sub : subs)
    if (sub->topic == topic) sub->send(s);
}

std::string RpcHttpServer::metrics_text() {
  Runtime& rt = svc_.runtime();
  std::ostringstream o;
  auto gauge = [&](const char* name, const char* help, uint64_t v) {
    o << "# HELP " << name << ' ' << help << "\n# TYPE " << name << " gauge\n" << name << ' ' << v << '\n';
  };
  gauge("morphe_height", "highest committed block height", rt.height());
  gauge("morphe_mempool_size", "pending transactions in the mempool", rt.app().mempool().size());
  gauge("morphe_peers", "reachable mesh peers", rt.peer_count());
  gauge("morphe_validators", "current validator set size", rt.node().member_count());
  gauge("morphe_evidence_count", "double-sign evidences observed", rt.evidence_count());
  gauge("morphe_is_validator", "1 if this node is currently a validator",
        rt.node().is_member(rt.key().pub) ? 1 : 0);
  return o.str();
}

void RpcHttpServer::attach_events() {
  svc_.runtime().app().add_on_commit([this](const CommitEvent& e) {
    publish("height", json::object{{"height", e.height},
                                   {"timestamp", e.timestamp},
                                   {"proposer", hex_encode(e.proposer.data(), e.proposer.size())}});
    for (const auto& t : e.txs)
      publish("tx", json::object{{"tx_id", hex_encode(t.first.data(), t.first.size())},
                                 {"height", e.height},
                                 {"applied", t.second}});
  });
}

} // namespace hyle::morphe
