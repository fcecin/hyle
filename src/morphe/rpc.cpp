#include <hyle/morphe/rpc.h>

#include <hyle/core/snapshot.h>
#include <hyle/services/hex.h>
#include <hyle/services/ops.h>
#include <hyle/services/schema.h>

#include <boost/json/src.hpp>

#include <fstream>
#include <sstream>

namespace json = boost::json;

namespace hyle::morphe {
using namespace hyle::services;

namespace {

constexpr int kErrInternal = -32603;
constexpr int kErrNotFound = -32004;

std::string hex(const uint8_t* p, size_t n) { return hex_encode(p, n); }
template <class Arr>
std::string hex(const Arr& a) { return hex_encode(a.data(), a.size()); }

wire::Bytes unhex(const std::string& s) {
  try {
    return hex_decode(s);
  } catch (const std::exception&) {
    throw RpcError{-32602, "invalid hex"};
  }
}

void enc_vset(wire::Writer& w, const malachite::ValidatorSet& vs) {
  w.count(vs.size());
  for (const auto& v : vs) {
    w.bytes(wire::View(v.address.data(), v.address.size()));
    w.bytes(wire::View(v.public_key.data(), v.public_key.size()));
    w.u64(v.voting_power);
  }
}
malachite::ValidatorSet dec_vset(wire::Reader& r) {
  malachite::ValidatorSet vs;
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) {
    malachite::Validator v;
    wire::View a = r.bytes();
    v.address.assign(a.begin(), a.end());
    wire::View pk = r.bytes();
    v.public_key.assign(pk.begin(), pk.end());
    v.voting_power = r.u64();
    vs.push_back(std::move(v));
  }
  return vs;
}
wire::Bytes enc_snapshot(const Snapshot& s) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(s.height);
  w.bytes(wire::View(s.governance.data(), s.governance.size()));
  w.bytes(wire::View(s.app.data(), s.app.size()));
  enc_vset(w, s.next_set);
  enc_vset(w, s.next_set2);
  w.count(s.attestations.size());
  for (const auto& a : s.attestations) {
    w.u64(a.height);
    w.raw(wire::View(a.app_hash.data(), a.app_hash.size()));
    w.raw(wire::View(a.signer.data(), a.signer.size()));
    w.raw(wire::View(a.sig.data(), a.sig.size()));
  }
  return out;
}
Snapshot dec_snapshot(wire::View in) {
  wire::Reader r(in);
  Snapshot s;
  s.height = r.u64();
  wire::View g = r.bytes();
  s.governance.assign(g.begin(), g.end());
  wire::View ap = r.bytes();
  s.app.assign(ap.begin(), ap.end());
  s.next_set = dec_vset(r);
  s.next_set2 = dec_vset(r);
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) {
    Attestation a;
    a.height = r.u64();
    wire::View h = r.raw(32);
    std::copy(h.begin(), h.end(), a.app_hash.begin());
    wire::View sg = r.raw(32);
    std::copy(sg.begin(), sg.end(), a.signer.begin());
    wire::View si = r.raw(64);
    std::copy(si.begin(), si.end(), a.sig.begin());
    s.attestations.push_back(a);
  }
  if (!r.empty()) throw wire::Error("morphe: snapshot has trailing bytes");
  return s;
}

std::string get_str(const json::object& p, const char* k) {
  auto it = p.find(k);
  if (it == p.end() || !it->value().is_string()) throw RpcError{-32602, std::string("missing param: ") + k};
  return std::string(it->value().as_string().c_str());
}
PubKey get_pubkey(const json::object& p, const char* k) {
  wire::Bytes b = unhex(get_str(p, k));
  if (b.size() != 32) throw RpcError{-32602, "pubkey must be 32 bytes"};
  PubKey pk{};
  std::copy(b.begin(), b.end(), pk.begin());
  return pk;
}

}  // namespace

boost::json::value RpcService::handle(const std::string& method, const json::object& p) {
 try {
  if (method == "submit_tx") return submit_tx(p);
  if (method == "query.balance") return q_balance(p);
  if (method == "query.account") return q_account(p);
  if (method == "query.entry") return q_entry(p);
  if (method == "query.height") return q_height();
  if (method == "query.apphash") return q_apphash();
  if (method == "query.validators") return q_validators();
  if (method == "query.governance") return q_governance();
  if (method == "query.mempool") return q_mempool();
  if (method == "query.tx") return q_tx(p);
  if (method == "status") return q_status();

  if (method == "admin.snapshot_dump") return admin_snapshot_dump(p);
  if (method == "admin.snapshot_load") return admin_snapshot_load(p);
  if (method == "admin.set_log_level")
    return json::object{{"ok", false}, {"reason", "not implemented"}};
  if (method == "admin.leave") {
    rt_.vote_remove(rt_.key().pub);
    return json::object{{"ok", true}, {"leaving", hex(rt_.key().pub)}};
  }
  if (method == "admin.gov_vote") {
    const std::string kind = get_str(p, "kind");
    const PubKey target = get_pubkey(p, "target");
    if (kind == "add") rt_.vote_add(target);
    else if (kind == "remove") rt_.vote_remove(target);
    else throw RpcError{-32602, "kind must be add|remove"};
    return json::object{{"ok", true}, {"kind", kind}, {"target", hex(target)}};
  }
  if (method == "admin.shutdown") return admin_shutdown();
  throw RpcError{-32601, "method not found: " + method};
 } catch (const RpcError&) {
  throw;
 } catch (const std::exception&) {
  // Any other escape becomes a uniform internal error; what() is kept off the wire.
  throw RpcError{-32603, "internal error"};
 }
}

boost::json::value RpcService::submit_tx(const json::object& p) {
  wire::Bytes raw = unhex(get_str(p, "tx"));
  Decoded d;
  try {
    d = decode_ops(wire::View(raw.data(), raw.size()));
  } catch (const wire::Error&) {
    throw RpcError{-32602, "malformed tx bytes"};
  }
  const size_t total = d.transfers.size() + d.entries.size();
  if (total == 0) throw RpcError{-32602, "empty tx"};
  if (total > 1)
    throw RpcError{-32602, "submit_tx takes exactly one op; got " + std::to_string(total) +
                               " (submit them separately)"};
  Admit a = Admit::BadShape;
  Hash id{};
  const std::string& cid = rt_.app().chain_id();
  const wire::View cv(reinterpret_cast<const uint8_t*>(cid.data()), cid.size());
  if (!d.transfers.empty()) { a = rt_.submit(d.transfers[0]); id = tx_id(cv, d.transfers[0]); }
  else { a = rt_.submit(d.entries[0]); id = tx_id(cv, d.entries[0]); }
  return json::object{{"tx_id", hex(id)}, {"accepted", a == Admit::Ok}, {"reason", admit_reason(a)}};
}

boost::json::value RpcService::q_balance(const json::object& p) {
  const PubKey k = get_pubkey(p, "pubkey");
  return json::object{{"balance", rt_.app().balance(k)}};
}

boost::json::value RpcService::q_account(const json::object& p) {
  const PubKey k = get_pubkey(p, "pubkey");
  const App& app = rt_.app();
  return json::object{{"balance", app.balance(k)},
                      {"sequence", app.sequence(k)},
                      {"exists", app.account_exists(k)}};
}

boost::json::value RpcService::q_entry(const json::object& p) {
  wire::Bytes name = unhex(get_str(p, "name"));
  Entry e;
  if (!rt_.app().entry_info(wire::View(name.data(), name.size()), e))
    throw RpcError{kErrNotFound, "entry not found"};
  return json::object{{"owner", hex(e.owner)},
                      {"balance", e.balance},
                      {"created", e.created},
                      {"last_modified", e.last_modified},
                      {"last_rent", e.last_rent},
                      {"payload", hex(e.payload.data(), e.payload.size())}};
}

boost::json::value RpcService::q_height() {
  return json::object{{"height", rt_.height()}, {"chain_id", rt_.app().chain_id()}};
}

boost::json::value RpcService::q_apphash() {
  const Hash h = rt_.node().composite_hash();
  return json::object{{"apphash", hex(h)}};
}

boost::json::value RpcService::q_validators() {
  uint64_t h = rt_.node().applied_height();
  const malachite::ValidatorSet vs = rt_.node().validators_for(h == 0 ? 1 : h);
  json::array out;
  for (const auto& v : vs) out.push_back(json::value(hex(v.public_key.data(), v.public_key.size())));
  return json::object{{"validators", out}, {"count", static_cast<uint64_t>(vs.size())}};
}

boost::json::value RpcService::q_governance() {
  return json::object{{"members", static_cast<uint64_t>(rt_.node().member_count())}};
}

boost::json::value RpcService::q_mempool() {
  return json::object{{"size", static_cast<uint64_t>(rt_.app().mempool().size())}};
}

boost::json::value RpcService::q_tx(const json::object& p) {
  wire::Bytes idb = unhex(get_str(p, "tx_id"));
  if (idb.size() != 32) throw RpcError{-32602, "tx_id must be 32 bytes"};
  Hash id{};
  std::copy(idb.begin(), idb.end(), id.begin());
  TxResult r;
  if (!rt_.app().tx_result(id, r))
    return json::object{{"committed", false}};
  return json::object{{"committed", true}, {"height", r.height}, {"applied", r.applied}};
}

boost::json::value RpcService::q_status() {
  const App& app = rt_.app();
  return json::object{{"height", rt_.height()},
                      {"applied_height", rt_.node().applied_height()},
                      {"apphash", hex(rt_.node().composite_hash())},
                      {"validators", static_cast<uint64_t>(rt_.node().member_count())},
                      {"is_validator", rt_.node().is_member(rt_.key().pub)},
                      {"mempool", static_cast<uint64_t>(app.mempool().size())}};
}

boost::json::value RpcService::admin_snapshot_dump(const json::object& p) {
  const std::string path = get_str(p, "path");
  const Snapshot s = rt_.node().build_snapshot({});
  const wire::Bytes snap = enc_snapshot(s);
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  if (!f) throw RpcError{kErrInternal, "cannot write snapshot"};
  f.write(reinterpret_cast<const char*>(snap.data()), static_cast<std::streamsize>(snap.size()));
  f.close();
  if (!f) throw RpcError{kErrInternal, "snapshot write failed (disk full?); file may be truncated"};
  return json::object{{"ok", true},
                      {"height", s.height},
                      {"bytes", static_cast<uint64_t>(snap.size())},
                      {"apphash", hex(rt_.node().composite_hash())}};
}

boost::json::value RpcService::admin_snapshot_load(const json::object& p) {
  const std::string path = get_str(p, "path");
  std::ifstream f(path, std::ios::binary);
  if (!f) throw RpcError{kErrInternal, "cannot read snapshot"};
  std::ostringstream ss;
  ss << f.rdbuf();
  const std::string s = ss.str();
  wire::Bytes b(s.begin(), s.end());
  Snapshot snap;
  try {
    snap = dec_snapshot(wire::View(b.data(), b.size()));
  } catch (const wire::Error& e) {
    throw RpcError{kErrInternal, std::string("malformed snapshot: ") + e.what()};
  }
  if (!rt_.node().restore_snapshot(snap)) throw RpcError{kErrInternal, "snapshot rejected"};
  return json::object{{"ok", true}, {"height", snap.height}, {"apphash", hex(rt_.node().composite_hash())}};
}

boost::json::value RpcService::admin_shutdown() {
  rt_.stop();
  return json::object{{"ok", true}};
}

} // namespace hyle::morphe
