#include <hyle/services/keys.h>

#include <hyle/services/hex.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <stdexcept>

namespace hyle::services {

void save_key(const std::string& path, const KeyPair& kp) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) throw std::runtime_error("services: cannot write key file " + path);
  ::fchmod(fd, 0600);
  const std::string line = hex_encode(kp.priv.data(), 32) + "\n";
  const ssize_t wrote = ::write(fd, line.data(), line.size());
  const int closed = ::close(fd);
  if (wrote != static_cast<ssize_t>(line.size()) || closed != 0)
    throw std::runtime_error("services: key file write failed (disk full?): " + path);
}

KeyPair load_key(const std::string& path) {
  std::ifstream f(path);
  if (!f) throw std::runtime_error("services: cannot read key file " + path);
  std::string line;
  std::getline(f, line);
  while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
    line.pop_back();
  return KeyPair::from_secret(hex_decode_fixed<32>(line));
}

std::string pubkey_hex(const PubKey& pk) { return hex_encode(pk.data(), pk.size()); }

PubKey pubkey_from_hex(const std::string& s) { return hex_decode_fixed<32>(s); }

} // namespace hyle::services
