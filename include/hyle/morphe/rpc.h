#ifndef HYLE_MORPHE_RPC_H
#define HYLE_MORPHE_RPC_H

#include <hyle/services/runtime.h>

#include <boost/json.hpp>

#include <exception>
#include <string>

namespace hyle::morphe {

struct RpcError : std::exception {
  int code;
  std::string message;
  RpcError(int c, std::string m) : code(c), message(std::move(m)) {}
  const char* what() const noexcept override { return message.c_str(); }
};

class RpcService {
public:
  explicit RpcService(Runtime& rt) : rt_(rt) {}

  boost::json::value handle(const std::string& method, const boost::json::object& params);

  Runtime& runtime() { return rt_; }

private:
  boost::json::value submit_tx(const boost::json::object& p);
  boost::json::value q_balance(const boost::json::object& p);
  boost::json::value q_account(const boost::json::object& p);
  boost::json::value q_entry(const boost::json::object& p);
  boost::json::value q_height();
  boost::json::value q_apphash();
  boost::json::value q_validators();
  boost::json::value q_governance();
  boost::json::value q_mempool();
  boost::json::value q_tx(const boost::json::object& p);
  boost::json::value q_status();

  boost::json::value admin_snapshot_dump(const boost::json::object& p);
  boost::json::value admin_snapshot_load(const boost::json::object& p);
  boost::json::value admin_shutdown();

  Runtime& rt_;
};

} // namespace hyle::morphe

#endif
