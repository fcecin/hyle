#include <hyle/services/keyring.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>

namespace fs = std::filesystem;

namespace hyle::services {

namespace {
std::string g_override;
}

void set_keyring_dir(const std::string& dir) { g_override = dir; }

std::string keyring_dir() {
  if (!g_override.empty()) return g_override;
  if (const char* e = std::getenv("TECHNE_KEYS"); e && *e) return e;
  if (const char* h = std::getenv("HOME"); h && *h) return std::string(h) + "/.morphe/keys";
  return "./.morphe/keys";
}

bool valid_key_name(const std::string& name) {
  if (name.empty() || name == "." || name == "..") return false;
  for (char c : name) {
    const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '_' || c == '.' || c == '-';
    if (!ok) return false;
  }
  return true;
}

std::string key_path(const std::string& name) {
  if (!valid_key_name(name))
    throw std::runtime_error("illegal key name '" + name + "' (allowed: letters, digits, _ . -)");
  return keyring_dir() + "/" + name + ".key";
}

std::vector<std::string> list_key_names() {
  std::vector<std::string> out;
  const std::string dir = keyring_dir();
  std::error_code ec;
  if (!fs::is_directory(dir, ec)) return out;
  for (auto it = fs::directory_iterator(dir, ec); !ec && it != fs::directory_iterator();
       it.increment(ec)) {
    const auto& e = *it;
    if (!e.is_regular_file(ec)) continue;
    const std::string fn = e.path().filename().string();
    if (fn.size() > 4 && fn.substr(fn.size() - 4) == ".key") {
      const std::string name = fn.substr(0, fn.size() - 4);
      if (valid_key_name(name)) out.push_back(name);
    }
  }
  std::sort(out.begin(), out.end());
  return out;
}

} // namespace hyle::services
