#ifndef HYLE_MORPHE_KEYRING_H
#define HYLE_MORPHE_KEYRING_H

#include <string>
#include <vector>

namespace hyle::morphe {

std::string keyring_dir();

void set_keyring_dir(const std::string& dir);

bool valid_key_name(const std::string& name);

std::string key_path(const std::string& name);

std::vector<std::string> list_key_names();

} // namespace hyle::morphe

#endif
