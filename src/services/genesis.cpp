#include <hyle/services/genesis.h>

#include <hyle/services/hex.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace hyle::services {

namespace {

void put_key(wire::Writer& w, const PubKey& k) { w.raw(wire::View(k.data(), k.size())); }

uint64_t parse_u64(const std::string& s) {
  uint64_t v = 0;
  const char* first = s.data();
  const char* last = s.data() + s.size();
  const auto res = std::from_chars(first, last, v);
  if (res.ec != std::errc{} || res.ptr != last)
    throw std::runtime_error("genesis: invalid unsigned integer '" + s + "'");
  return v;
}

} // namespace

// A Config field left out of canonical() drops it from the genesis hash and can cause a fork.
static_assert(sizeof(Config) == 88,
              "Config changed: update genesis canonical()/parse()/to_text() and this size");

wire::Bytes Genesis::canonical() const {
  std::vector<PubKey> vs = validators;
  std::sort(vs.begin(), vs.end());
  std::vector<std::pair<PubKey, uint64_t>> al = allocations;
  std::sort(al.begin(), al.end());

  wire::Bytes out;
  wire::Writer w(out);
  w.str("MORPHE_GENESIS_V1");
  w.bytes(wire::View(reinterpret_cast<const uint8_t*>(chain_id.data()), chain_id.size()));
  w.u64(config.fee_transfer);
  w.u64(config.fee_entry);
  w.u64(config.fee_sudo);
  w.u64(config.rent_rate);
  w.u64(config.rip_bounty);
  w.u64(config.sudo_ttl_secs);
  w.u64(config.pbts_window_secs);
  w.u64(config.member_cap);
  w.u64(config.member_floor);
  w.u64(config.max_value_bytes);
  w.u64(config.credit_autofill_ceiling);
  w.u64(config.refill_rate);
  w.count(vs.size());
  for (const auto& v : vs) put_key(w, v);
  w.count(al.size());
  for (const auto& a : al) {
    put_key(w, a.first);
    w.u64(a.second);
  }
  return out;
}

Hash Genesis::hash() const {
  const wire::Bytes c = canonical();
  return sha256(wire::View(c.data(), c.size()));
}

bool Genesis::validate(std::string& err) const {
  if (chain_id.empty()) { err = "chain_id is empty"; return false; }
  for (unsigned char c : chain_id)
    if (c < 0x20 || c > 0x7e || c == '"' || c == '\\') {
      err = "chain_id must be printable ASCII without quote or backslash";
      return false;
    }
  if (validators.empty()) { err = "no genesis validators"; return false; }
  std::vector<PubKey> vs = validators;
  std::sort(vs.begin(), vs.end());
  if (std::adjacent_find(vs.begin(), vs.end()) != vs.end()) {
    err = "duplicate genesis validator";
    return false;
  }
  std::vector<PubKey> ak;
  ak.reserve(allocations.size());
  for (const auto& a : allocations) ak.push_back(a.first);
  std::sort(ak.begin(), ak.end());
  if (std::adjacent_find(ak.begin(), ak.end()) != ak.end()) {
    err = "duplicate allocation pubkey";
    return false;
  }
  if (config.rent_rate > 0 &&
      config.rip_bounty > std::min(config.fee_transfer, config.fee_entry)) {
    err = "with rent_rate>0, rip_bounty must not exceed min(fee_transfer,fee_entry) (inflation pump)";
    return false;
  }
  if (config.pbts_window_secs == 0) {
    err = "pbts_window_secs must be > 0 (a 0 window rejects every block whose timestamp differs "
          "from local time, so the chain cannot produce)";
    return false;
  }
  return true;
}

Genesis Genesis::parse(const std::string& text) {
  Genesis g;
  std::istringstream in(text);
  std::string line;
  size_t lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
    std::istringstream ls(line);
    std::string key;
    if (!(ls >> key)) continue;
    if (key.empty() || key[0] == '#') continue;
    std::string a, b;
    auto need = [&](std::string& dst) {
      if (!(ls >> dst))
        throw std::runtime_error("genesis: line " + std::to_string(lineno) + ": missing argument");
    };
    if (key == "chain_id") { need(a); g.chain_id = a; }
    else if (key == "validator") { need(a); g.validators.push_back(hex_decode_fixed<32>(a)); }
    else if (key == "alloc") { need(a); need(b); g.allocations.emplace_back(hex_decode_fixed<32>(a), parse_u64(b)); }
    else if (key == "fee_transfer") { need(a); g.config.fee_transfer = parse_u64(a); }
    else if (key == "fee_entry") { need(a); g.config.fee_entry = parse_u64(a); }
    else if (key == "fee_sudo") { need(a); g.config.fee_sudo = parse_u64(a); }
    else if (key == "rent_rate") { need(a); g.config.rent_rate = parse_u64(a); }
    else if (key == "rip_bounty") { need(a); g.config.rip_bounty = parse_u64(a); }
    else if (key == "sudo_ttl_secs") { need(a); g.config.sudo_ttl_secs = parse_u64(a); }
    else if (key == "pbts_window_secs") { need(a); g.config.pbts_window_secs = parse_u64(a); }
    else if (key == "member_cap") { need(a); g.config.member_cap = static_cast<unsigned>(parse_u64(a)); }
    else if (key == "member_floor") { need(a); g.config.member_floor = static_cast<unsigned>(parse_u64(a)); }
    else if (key == "max_value_bytes") { need(a); g.config.max_value_bytes = parse_u64(a); }
    else if (key == "credit_autofill_ceiling") { need(a); g.config.credit_autofill_ceiling = parse_u64(a); }
    else if (key == "refill_rate") { need(a); g.config.refill_rate = parse_u64(a); }
    else throw std::runtime_error("genesis: line " + std::to_string(lineno) + ": unknown key '" + key + "'");
  }
  std::string err;
  if (!g.validate(err)) throw std::runtime_error("genesis: invalid: " + err);
  return g;
}

std::string Genesis::to_text() const {
  std::vector<PubKey> vs = validators;
  std::sort(vs.begin(), vs.end());
  std::vector<std::pair<PubKey, uint64_t>> al = allocations;
  std::sort(al.begin(), al.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

  std::ostringstream o;
  o << "chain_id " << chain_id << "\n";
  o << "fee_transfer " << config.fee_transfer << "\n";
  o << "fee_entry " << config.fee_entry << "\n";
  o << "fee_sudo " << config.fee_sudo << "\n";
  o << "rent_rate " << config.rent_rate << "\n";
  o << "rip_bounty " << config.rip_bounty << "\n";
  o << "sudo_ttl_secs " << config.sudo_ttl_secs << "\n";
  o << "pbts_window_secs " << config.pbts_window_secs << "\n";
  o << "member_cap " << config.member_cap << "\n";
  o << "member_floor " << config.member_floor << "\n";
  o << "max_value_bytes " << config.max_value_bytes << "\n";
  o << "credit_autofill_ceiling " << config.credit_autofill_ceiling << "\n";
  o << "refill_rate " << config.refill_rate << "\n";
  for (const auto& v : vs) o << "validator " << hex_encode(v.data(), 32) << "\n";
  for (const auto& a : al) o << "alloc " << hex_encode(a.first.data(), 32) << " " << a.second << "\n";
  return o.str();
}

} // namespace hyle::services
