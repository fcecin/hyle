#ifndef HYLE_SERVICES_GENESIS_H
#define HYLE_SERVICES_GENESIS_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>
#include <hyle/services/config.h>

#include <string>
#include <utility>
#include <vector>

namespace hyle::services {

struct Genesis {
  std::string chain_id;
  std::vector<PubKey> validators;
  std::vector<std::pair<PubKey, uint64_t>> allocations;
  Config config;

  wire::Bytes canonical() const;
  Hash hash() const;

  bool validate(std::string& err) const;

  static Genesis parse(const std::string& text);
  std::string to_text() const;
};

} // namespace hyle::services

#endif
