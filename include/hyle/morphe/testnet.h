#ifndef HYLE_MORPHE_TESTNET_H
#define HYLE_MORPHE_TESTNET_H

#include <hyle/core/crypto.h>
#include <hyle/services/genesis.h>

#include <cstdint>
#include <string>
#include <vector>

namespace hyle::morphe {
using namespace hyle::services;

struct TestnetPeer {
  PubKey pk{};
  std::string host;
  uint16_t port = 0;
};

Genesis generate_testnet(const std::string& dir, int n, uint16_t base_port);

std::vector<TestnetPeer> parse_peers(const std::string& home);

uint64_t read_config_u64(const std::string& home, const std::string& key, uint64_t def);
std::string read_config_str(const std::string& home, const std::string& key, const std::string& def);

} // namespace hyle::morphe

#endif
