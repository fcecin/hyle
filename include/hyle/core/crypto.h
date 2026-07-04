#ifndef HYLE_CRYPTO_H
#define HYLE_CRYPTO_H

#include <hyle/core/wire.h>

#include <array>
#include <cstdint>

namespace hyle {

using PubKey = std::array<uint8_t, 32>;
using PrivKey = std::array<uint8_t, 32>;
using Sig = std::array<uint8_t, 64>;
using Hash = std::array<uint8_t, 32>;

struct KeyPair {
  PrivKey priv{};
  PubKey pub{};

  KeyPair() = default;
  KeyPair(const KeyPair&) = default;
  KeyPair& operator=(const KeyPair&) = default;
  // a volatile write is not elided as a dead store
  ~KeyPair() {
    for (volatile uint8_t& b : priv) b = 0;
  }

  static KeyPair generate();
  static KeyPair from_secret(const PrivKey& secret);

  Sig sign(wire::View msg) const;
};

bool verify(const PubKey& pub, wire::View msg, const Sig& sig);

Hash sha256(wire::View data);

} // namespace hyle

#endif
