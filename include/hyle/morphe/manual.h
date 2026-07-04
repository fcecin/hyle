#ifndef HYLE_MORPHE_MANUAL_H
#define HYLE_MORPHE_MANUAL_H

#include <string>
#include <vector>

namespace hyle::morphe::manual {

const std::vector<std::pair<std::string, std::string>>& topics();

const std::string* lookup(const std::string& name);

} // namespace hyle::morphe::manual

#endif
