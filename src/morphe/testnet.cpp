#include <hyle/morphe/testnet.h>

#include <hyle/services/keys.h>

#include <charconv>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace fs = std::filesystem;

namespace hyle::morphe {
using namespace hyle::services;

namespace {
void write_file(const std::string& path, const std::string& content) {
  std::ofstream f(path, std::ios::trunc);
  if (!f) throw std::runtime_error("testnet: cannot write " + path);
  f << content;
}
std::string read_file(const std::string& path) {
  std::ifstream f(path);
  if (!f) return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}
} // namespace

Genesis generate_testnet(const std::string& dir, int n, uint16_t base_port) {
  if (n < 1) throw std::runtime_error("testnet: need at least one validator");
  if (static_cast<int>(base_port) + 2000 + (n - 1) > 0xffff)
    throw std::runtime_error("testnet: base_port too high; base_port + 2000 + n must be <= 65535");

  std::vector<KeyPair> kps;
  Genesis g;
  g.chain_id = "morphe-testnet";
  for (int i = 0; i < n; ++i) {
    KeyPair kp = KeyPair::generate();
    kps.push_back(kp);
    g.validators.push_back(kp.pub);
    g.allocations.emplace_back(kp.pub, 1000000);
  }
  const std::string genesis_text = g.to_text();

  fs::create_directories(dir);
  for (int i = 0; i < n; ++i) {
    const std::string home = dir + "/node" + std::to_string(i);
    fs::create_directories(home);
    save_key(home + "/node.key", kps[i]);
    write_file(home + "/genesis.txt", genesis_text);

    std::ostringstream cfg;
    cfg << "block_pace_ms 1000\n";
    cfg << "listen_port " << static_cast<unsigned>(base_port + i) << "\n";
    cfg << "control_port " << static_cast<unsigned>(base_port + 1000 + i) << "\n";
    cfg << "client_port " << static_cast<unsigned>(base_port + 2000 + i) << "\n";
    write_file(home + "/config.txt", cfg.str());

    std::ostringstream peers;
    for (int j = 0; j < n; ++j) {
      if (j == i) continue;
      peers << pubkey_hex(kps[j].pub) << " 127.0.0.1 " << static_cast<unsigned>(base_port + j) << "\n";
    }
    write_file(home + "/peers.txt", peers.str());
  }
  return g;
}

std::vector<TestnetPeer> parse_peers(const std::string& home) {
  std::vector<TestnetPeer> out;
  std::istringstream in(read_file(home + "/peers.txt"));
  std::string line;
  size_t lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
    std::istringstream ls(line);
    std::string hex, host, extra;
    unsigned port = 0;
    if (!(ls >> hex)) continue;
    if (hex.empty() || hex[0] == '#') continue;
    if (!(ls >> host >> port) || (ls >> extra))
      throw std::runtime_error("testnet: peers.txt line " + std::to_string(lineno) +
                               ": expected '<pubkey_hex> <host> <port>'");
    if (port > 0xffff)
      throw std::runtime_error("testnet: peer port out of range (line " + std::to_string(lineno) + ")");
    out.push_back(TestnetPeer{pubkey_from_hex(hex), host, static_cast<uint16_t>(port)});
  }
  return out;
}

uint64_t read_config_u64(const std::string& home, const std::string& key, uint64_t def) {
  std::istringstream in(read_file(home + "/config.txt"));
  std::string k, v;
  while (in >> k >> v)
    if (k == key) {
      uint64_t out = 0;
      const auto r = std::from_chars(v.data(), v.data() + v.size(), out);
      return (r.ec == std::errc{} && r.ptr == v.data() + v.size()) ? out : def;
    }
  return def;
}

std::string read_config_str(const std::string& home, const std::string& key, const std::string& def) {
  std::istringstream in(read_file(home + "/config.txt"));
  std::string k, v;
  while (in >> k >> v)
    if (k == key) return v;
  return def;
}

} // namespace hyle::morphe
