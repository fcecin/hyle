#ifndef HYLE_SERVICES_KEYS_H
#define HYLE_SERVICES_KEYS_H

#include <hyle/core/crypto.h>

#include <string>

namespace hyle::services {

void save_key(const std::string& path, const KeyPair& kp);
KeyPair load_key(const std::string& path);
std::string pubkey_hex(const PubKey& pk);
PubKey pubkey_from_hex(const std::string& s);

} // namespace hyle::services

#endif
