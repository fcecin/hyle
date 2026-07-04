#ifndef HYLE_MORPHE_HEX_H
#define HYLE_MORPHE_HEX_H

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace hyle::morphe {

inline std::string hex_encode(const uint8_t* p, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(H[p[i] >> 4]);
    s.push_back(H[p[i] & 0x0f]);
  }
  return s;
}

inline bool hex_nibble(char c, uint8_t& out) {
  if (c >= '0' && c <= '9') { out = static_cast<uint8_t>(c - '0'); return true; }
  if (c >= 'a' && c <= 'f') { out = static_cast<uint8_t>(c - 'a' + 10); return true; }
  if (c >= 'A' && c <= 'F') { out = static_cast<uint8_t>(c - 'A' + 10); return true; }
  return false;
}

inline bool hex_try_decode(const std::string& s, std::vector<uint8_t>& out) {
  out.clear();
  if (s.size() % 2 != 0) return false;
  out.reserve(s.size() / 2);
  for (size_t i = 0; i < s.size(); i += 2) {
    uint8_t hi = 0, lo = 0;
    if (!hex_nibble(s[i], hi) || !hex_nibble(s[i + 1], lo)) { out.clear(); return false; }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

inline std::vector<uint8_t> hex_decode(const std::string& s) {
  std::vector<uint8_t> out;
  if (!hex_try_decode(s, out)) throw std::invalid_argument("invalid hex");
  return out;
}

template <size_t N>
std::array<uint8_t, N> hex_decode_fixed(const std::string& s) {
  if (s.size() != 2 * N)
    throw std::invalid_argument("hex: expected " + std::to_string(2 * N) + " chars, got " +
                                std::to_string(s.size()));
  std::array<uint8_t, N> out{};
  for (size_t i = 0; i < N; ++i) {
    uint8_t hi = 0, lo = 0;
    if (!hex_nibble(s[2 * i], hi) || !hex_nibble(s[2 * i + 1], lo))
      throw std::invalid_argument("invalid hex char");
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return out;
}

}  // namespace hyle::morphe

#endif
