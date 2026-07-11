#include <hyle/services/hex.h>
#include <hyle/services/keyring.h>
#include <hyle/services/keys.h>
#include <hyle/services/ops.h>
#include <hyle/services/schema.h>

#include <CLI/CLI.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <exception>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;
using namespace hyle;

namespace {

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

bool g_raw = false;

std::string to_hex_str(const uint8_t* p, size_t n) { return services::hex_encode(p, n); }
wire::Bytes unhex(const std::string& s) { return services::hex_decode(s); }

struct Endpoint { std::string host; uint16_t port; };

Endpoint parse_endpoint(const std::string& arg, const char* env, const char* which) {
  std::string s = arg;
  if (s.empty()) { const char* e = std::getenv(env); if (e) s = e; }
  if (s.empty())
    throw std::runtime_error(std::string("no ") + which + " endpoint (use --" + which +
                             " host:port or set " + env + ")");
  const auto c = s.rfind(':');
  if (c == std::string::npos) throw std::runtime_error("endpoint must be host:port, got '" + s + "'");
  return {s.substr(0, c), static_cast<uint16_t>(std::stoul(s.substr(c + 1)))};
}

std::string http_req(const Endpoint& ep, http::verb verb, const std::string& target,
                     const std::string& body) {
  boost::asio::io_context io;
  tcp::resolver res(io);
  tcp::socket sock(io);
  boost::asio::connect(sock, res.resolve(ep.host, std::to_string(ep.port)));
  http::request<http::string_body> req(verb, target, 11);
  req.set(http::field::host, ep.host);
  if (!body.empty()) {
    req.set(http::field::content_type, "application/json");
    req.body() = body;
  }
  req.prepare_payload();
  http::write(sock, req);
  beast::flat_buffer b;
  http::response<http::string_body> resp;
  http::read(sock, b, resp);
  beast::error_code ec;
  sock.shutdown(tcp::socket::shutdown_both, ec);
  return resp.body();
}

std::string extract_result(const std::string& env) {
  if (env.find("\"error\":") != std::string::npos) return env;
  const auto r = env.find("\"result\":");
  if (r == std::string::npos) return env;
  std::string v = env.substr(r + 9);
  auto rstrip = [&] { while (!v.empty() && (v.back() == '\n' || v.back() == '\r' || v.back() == ' ')) v.pop_back(); };
  rstrip();
  if (!v.empty() && v.back() == '}') v.pop_back();
  rstrip();
  return v;
}

KeyPair load_signer(const std::string& key) {
  if (key.empty()) throw std::runtime_error("no signer (pass --key <name|file>)");
  const bool looks_path = key.find('/') != std::string::npos ||
                          (key.size() > 4 && key.substr(key.size() - 4) == ".key");
  return services::load_key(looks_path ? key : services::key_path(key));
}

std::string resolve_pubkey(const std::string& s) {
  if (s.empty() || s[0] != '@') return s;
  const std::string rest = s.substr(1);
  std::string path;
  if (rest.find('/') != std::string::npos)
    path = fs::is_directory(rest) ? rest + "/node.key" : rest;
  else
    path = services::key_path(rest);
  return services::pubkey_hex(services::load_key(path).pub);
}

int rest_get(const Endpoint& ep, const std::string& route) {
  std::printf("%s\n", http_req(ep, http::verb::get, "/" + route, "").c_str());
  return 0;
}

std::string fetch_chain_id(const Endpoint& ep) {
  const std::string r = http_req(ep, http::verb::get, "/height", "");
  static const std::string tag = "\"chain_id\":\"";
  const auto p = r.find(tag);
  if (p == std::string::npos) throw std::runtime_error("cannot read chain_id from the node /height reply");
  const size_t start = p + tag.size();
  const size_t end = r.find('"', start);
  if (end == std::string::npos) throw std::runtime_error("malformed chain_id in the node /height reply");
  return r.substr(start, end - start);
}

uint64_t fetch_sequence(const Endpoint& ep, const std::string& pubkey_hex) {
  const std::string r = http_req(ep, http::verb::get, "/account/" + pubkey_hex, "");
  const auto p = r.find("\"sequence\":");
  if (p == std::string::npos)
    throw std::runtime_error("cannot auto-fill sequence: account not found (fund it, or pass --seq): " +
                             pubkey_hex);
  return std::strtoull(r.c_str() + p + 11, nullptr, 10);
}

int do_tx_transfer(const Endpoint& ep, const std::string& key, const std::string& to, uint64_t amount,
                   std::optional<uint64_t> seq_opt) {
  const KeyPair signer = load_signer(key);
  const std::string mypk = services::pubkey_hex(signer.pub);
  const uint64_t seq = seq_opt ? *seq_opt : fetch_sequence(ep, mypk);
  const std::string chain = fetch_chain_id(ep);
  const PubKey topk = services::pubkey_from_hex(resolve_pubkey(to));
  wire::Bytes dst;
  dst.push_back(services::ACCOUNT_PREFIX);
  dst.insert(dst.end(), topk.begin(), topk.end());
  const services::TransferOp op =
      services::make_transfer(signer, wire::View(dst.data(), dst.size()), amount, seq,
                            wire::View(reinterpret_cast<const uint8_t*>(chain.data()), chain.size()));
  services::Decoded d;
  d.transfers.push_back(op);
  const wire::Bytes b = services::encode_ops(d);
  std::printf("%s\n", http_req(ep, http::verb::post, "/tx", to_hex_str(b.data(), b.size())).c_str());
  return 0;
}

int do_tx_entry_put(const Endpoint& ep, const std::string& key, const std::string& name_hex,
                    uint64_t fund, std::optional<uint64_t> seq_opt, const std::string& payload_hex) {
  const KeyPair signer = load_signer(key);
  const uint64_t seq = seq_opt ? *seq_opt : fetch_sequence(ep, services::pubkey_hex(signer.pub));
  const std::string chain = fetch_chain_id(ep);
  const wire::Bytes name = unhex(name_hex);
  const wire::Bytes payload = unhex(payload_hex);
  const services::EntryOp op = services::make_entry_put(
      signer, wire::View(name.data(), name.size()), seq, fund,
      wire::View(payload.data(), payload.size()),
      wire::View(reinterpret_cast<const uint8_t*>(chain.data()), chain.size()));
  services::Decoded d;
  d.entries.push_back(op);
  const wire::Bytes b = services::encode_ops(d);
  std::printf("%s\n", http_req(ep, http::verb::post, "/tx", to_hex_str(b.data(), b.size())).c_str());
  return 0;
}

int control_rpc(const Endpoint& ep, const std::string& method, const std::string& params) {
  const std::string body =
      "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\",\"params\":" + params + ",\"id\":1}";
  const std::string reply = http_req(ep, http::verb::post, "/", body);
  std::printf("%s\n", g_raw ? reply.c_str() : extract_result(reply).c_str());
  return 0;
}

int key_gen(const std::string& name, bool force) {
  const std::string path = services::key_path(name);
  if (fs::exists(path) && !force)
    throw std::runtime_error("key '" + name + "' exists (use --force to overwrite): " + path);
  fs::create_directories(fs::path(path).parent_path());
  const KeyPair kp = KeyPair::generate();
  services::save_key(path, kp);
  std::printf("%s  %s\n", name.c_str(), services::pubkey_hex(kp.pub).c_str());
  return 0;
}
int key_ls() {
  for (const std::string& n : services::list_key_names()) {
    try { std::printf("%-16s %s\n", n.c_str(), services::pubkey_hex(services::load_key(services::key_path(n)).pub).c_str()); }
    catch (...) { std::printf("%-16s (unreadable)\n", n.c_str()); }
  }
  return 0;
}
int key_show(const std::string& name) {
  std::printf("%s\n", services::pubkey_hex(services::load_key(services::key_path(name)).pub).c_str());
  return 0;
}
int key_path_cmd(const std::string& name) { std::printf("%s\n", services::key_path(name).c_str()); return 0; }
int key_import(const std::string& name, const std::string& hex, bool force) {
  const std::string path = services::key_path(name);
  if (fs::exists(path) && !force) throw std::runtime_error("key '" + name + "' exists (use --force)");
  const wire::Bytes b = unhex(hex);
  if (b.size() != 32) throw std::runtime_error("private key must be 64 hex chars (32 bytes)");
  PrivKey pk{};
  std::copy(b.begin(), b.end(), pk.begin());
  fs::create_directories(fs::path(path).parent_path());
  const KeyPair kp = KeyPair::from_secret(pk);
  services::save_key(path, kp);
  std::printf("%s  %s\n", name.c_str(), services::pubkey_hex(kp.pub).c_str());
  return 0;
}
int key_export(const std::string& name) {
  const std::string path = services::key_path(name);
  const KeyPair kp = services::load_key(path);
  std::printf("%s\n", to_hex_str(kp.priv.data(), 32).c_str());
  return 0;
}
int key_rm(const std::string& name) {
  const std::string path = services::key_path(name);
  if (!fs::remove(path)) throw std::runtime_error("no such key: " + name);
  std::printf("removed %s\n", name.c_str());
  return 0;
}

int do_man() {
  std::printf(
      "TECHNE -- the Morphe client.\n\n"
      "Morphe splits into two binaries: `morphe` runs a SERVER (a node); `techne` is the CLIENT. A\n"
      "client is any identity that submits transactions -- it is NOT a node and has no node.key. It\n"
      "holds identities in a keyring and talks to a running chain by giving the ADDRESS of a morphe\n"
      "node. An address is machine plus port: host:port (e.g. 10.0.0.5:47000 or 127.0.0.1:47000). A\n"
      "morphe node exposes TWO ports, so there are two address flags:\n\n"
      "  --morphe-node host:port      the node's user-facing REST port (config: client_port). Submit txs,\n"
      "                               run per-key queries. Public, fee-gated. Env: TECHNE_MORPHE_NODE.\n"
      "  --morphe-control host:port   the node's JSON-RPC CONTROL port (config: control_port). Full power:\n"
      "                               gov / snapshot / shutdown; firewalled, no auth. Env: TECHNE_MORPHE_CONTROL.\n\n"
      "So `--morphe-node` says WHERE the morphe node is (its public REST address) and `--morphe-control`\n"
      "says where that same node's control plane is. tx and query use --morphe-node; gov and snapshot use\n"
      "--morphe-control. Short aliases exist: `--node` for --morphe-node, `--control` for --morphe-control.\n\n"
      "KEYRING (--keys <dir>, else $TECHNE_KEYS, else ~/.morphe/keys; one <name>.key per identity, 0600)\n"
      "  techne key gen <name>            create an identity\n"
      "  techne key ls                    list names -> pubkeys\n"
      "  techne key show|path <name>      pubkey / file path\n"
      "  techne key import <name> <hex>   store an existing 64-hex private key\n"
      "  techne key export <name>         print the private key (backup; handle with care)\n"
      "  techne key rm <name>             delete\n\n"
      "ADDRESSING: anywhere a pubkey is taken, @<name> means that keyring identity's pubkey; @<path>\n"
      "(with a slash) means a key file or a node home's node.key.\n\n"
      "EXAMPLES\n"
      "  export TECHNE_MORPHE_NODE=chainhost:47000\n"
      "  techne key gen alice\n"
      "  techne tx transfer --key alice @bob 100     # seq auto-fills; @bob = keyring bob's pubkey\n"
      "  techne query balance @bob\n"
      "  techne gov vote add --morphe-control node0host:46000 @newvalidator\n");
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  CLI::App app{"techne -- the Morphe client (keyring + tx/query over the client REST port).", "techne"};
  app.require_subcommand(1);
  app.set_version_flag("--version", "techne 0.0.0 (Hyle layer 3 client)");
  app.set_help_all_flag("--help-all", "Show help for every subcommand");
  app.add_flag("--raw", g_raw, "Print the full JSON-RPC envelope for control ops (place before the subcommand)");
  { static std::string keys_dir;
    app.add_option("--keys", keys_dir, "Keyring directory (overrides TECHNE_KEYS; place before the subcommand)")
        ->each([](const std::string& d) { services::set_keyring_dir(d); }); }
  app.footer(
      "Every command talks to a running node over one of its two ports. `tx` and `query` use the CLIENT "
      "port (pass `--morphe-node host:port`, or set TECHNE_MORPHE_NODE); `gov` and `snapshot` use the CONTROL port "
      "(pass `--morphe-control host:port`, or set TECHNE_MORPHE_CONTROL). Identities live in a keyring ($TECHNE_KEYS or "
      "~/.morphe/keys), and `@name` means that identity's public key. Learn everything: `techne man`, or "
      "append `--help` to any command.");

  int rc = 0;
  std::deque<std::string> S;
  auto sref = [&]() -> std::string* { S.emplace_back(); return &S.back(); };

  app.add_subcommand("man", "What techne is; ports, keyring, addressing, examples")
      ->callback([&rc] { rc = do_man(); });

  auto* key = app.add_subcommand("key", "Manage client identities in the keyring");
  key->require_subcommand(1);
  { std::string* n = sref(); static bool force = false;
    auto* c = key->add_subcommand("gen", "Generate a new identity");
    c->add_option("name", *n, "Identity name")->required();
    c->add_flag("--force", force, "Overwrite if it exists");
    c->callback([&rc, n] { rc = key_gen(*n, force); }); }
  key->add_subcommand("ls", "List identities (name -> pubkey)")->callback([&rc] { rc = key_ls(); });
  { std::string* n = sref();
    auto* c = key->add_subcommand("show", "Print an identity's pubkey");
    c->add_option("name", *n, "Identity name")->required();
    c->callback([&rc, n] { rc = key_show(*n); }); }
  { std::string* n = sref();
    auto* c = key->add_subcommand("path", "Print an identity's key file path");
    c->add_option("name", *n, "Identity name")->required();
    c->callback([&rc, n] { rc = key_path_cmd(*n); }); }
  { std::string* n = sref(); std::string* h = sref(); static bool force = false;
    auto* c = key->add_subcommand("import", "Store an existing private key under a name");
    c->add_option("name", *n, "Identity name")->required();
    c->add_option("hex", *h, "Private key (64 hex chars)")->required();
    c->add_flag("--force", force, "Overwrite if it exists");
    c->callback([&rc, n, h] { rc = key_import(*n, *h, force); }); }
  { std::string* n = sref();
    auto* c = key->add_subcommand("export", "Print an identity's PRIVATE key (backup; handle with care)");
    c->add_option("name", *n, "Identity name")->required();
    c->callback([&rc, n] { rc = key_export(*n); }); }
  { std::string* n = sref();
    auto* c = key->add_subcommand("rm", "Delete an identity");
    c->add_option("name", *n, "Identity name")->required();
    c->callback([&rc, n] { rc = key_rm(*n); }); }

  auto* tx = app.add_subcommand("tx", "Submit a signed transaction via a node's client REST port");
  tx->footer("Endpoint: `--morphe-node host:port` (or set TECHNE_MORPHE_NODE). Signer: `--key <name|file>`.");
  tx->require_subcommand(1);
  { std::string* cl = sref(); std::string* k = sref(); std::string* to = sref();
    static uint64_t amt = 0, seq = 0;
    auto* c = tx->add_subcommand("transfer", "Move credit to an account pubkey or @name");
    c->add_option("--morphe-node,--node", *cl, "Where the Morphe node is: host:port of its user-facing REST port (client_port). Env TECHNE_MORPHE_NODE.");
    c->add_option("--key", *k, "Signer: keyring name or key file")->required();
    c->add_option("to", *to, "Destination: account pubkey (64 hex) or @name")->required();
    c->add_option("amount", amt, "Amount to move")->required();
    CLI::Option* so = c->add_option("--seq", seq, "Sender sequence (nonce); omit to auto-fill");
    c->callback([&rc, cl, k, to, so] {
      rc = do_tx_transfer(parse_endpoint(*cl, "TECHNE_MORPHE_NODE", "morphe-node"), *k, *to, amt,
                          so->count() ? std::optional<uint64_t>(seq) : std::nullopt); }); }
  { std::string* cl = sref(); std::string* k = sref(); std::string* name = sref(); std::string* pl = sref();
    static uint64_t fund = 0, seq = 0;
    auto* c = tx->add_subcommand("entry-put", "Create/overwrite an entry (owner-signed)");
    c->add_option("--morphe-node,--node", *cl, "Where the Morphe node is: host:port of its user-facing REST port (client_port). Env TECHNE_MORPHE_NODE.");
    c->add_option("--key", *k, "Signer: keyring name or key file")->required();
    c->add_option("name", *name, "Entry name (hex)")->required();
    c->add_option("fund", fund, "Amount to fund the entry")->required();
    c->add_option("payload", *pl, "Entry payload (hex)")->required();
    CLI::Option* so = c->add_option("--seq", seq, "Owner sequence (nonce); omit to auto-fill");
    c->callback([&rc, cl, k, name, pl, so] {
      rc = do_tx_entry_put(parse_endpoint(*cl, "TECHNE_MORPHE_NODE", "morphe-node"), *k, *name, fund,
                           so->count() ? std::optional<uint64_t>(seq) : std::nullopt, *pl); }); }

  auto* q = app.add_subcommand("query", "Read chain state (per-key reads via client REST)");
  q->footer("Endpoint: per-key reads use `--morphe-node host:port` (TECHNE_MORPHE_NODE); validators/apphash/status/"
            "mempool/governance use `--morphe-control host:port` (TECHNE_MORPHE_CONTROL).");
  q->require_subcommand(1);
  auto add_q = [&](const char* name, const char* desc, bool takes_pubkey, const char* route_prefix) {
    std::string* cl = sref();
    std::string* arg = takes_pubkey ? sref() : nullptr;
    auto* sc = q->add_subcommand(name, desc);
    sc->add_option("--morphe-node,--node", *cl, "Where the Morphe node is: host:port of its user-facing REST port (client_port). Env TECHNE_MORPHE_NODE.");
    if (arg) sc->add_option("arg", *arg, "pubkey/@name, entry name, or tx id")->required();
    sc->callback([&rc, cl, arg, route_prefix] {
      const Endpoint ep = parse_endpoint(*cl, "TECHNE_MORPHE_NODE", "morphe-node");
      std::string route = route_prefix;
      if (arg) { const bool pk = route == "balance" || route == "account";
                 route += "/" + (pk ? resolve_pubkey(*arg) : *arg); }
      rc = rest_get(ep, route); });
  };
  add_q("balance", "Account balance for a pubkey/@name (client port)", true, "balance");
  add_q("account", "Account {balance, sequence, exists} (client port)", true, "account");
  add_q("entry", "Entry record by name (hex) (client port)", true, "entry");
  add_q("tx", "Transaction receipt by id (client port)", true, "tx");
  add_q("height", "Current committed height (client port)", false, "height");

  auto add_cq = [&](const char* name, const char* desc, const char* method) {
    std::string* co = sref();
    auto* sc = q->add_subcommand(name, desc);
    sc->add_option("--morphe-control,--control", *co, "The Morphe node's control address: host:port of its JSON-RPC control port (control_port). Env TECHNE_MORPHE_CONTROL.");
    sc->callback([&rc, co, method] {
      rc = control_rpc(parse_endpoint(*co, "TECHNE_MORPHE_CONTROL", "morphe-control"), method, "{}"); });
  };
  add_cq("validators", "Current validator set (control port)", "query.validators");
  add_cq("apphash", "Current composite AppHash (control port)", "query.apphash");
  add_cq("status", "Node status (control port)", "status");
  add_cq("mempool", "Pending mempool size (control port)", "query.mempool");
  add_cq("governance", "Governance member count (control port)", "query.governance");

  auto* gov = app.add_subcommand("gov", "Membership governance via a node's control port");
  gov->footer("Endpoint: `--morphe-control host:port` (or set TECHNE_MORPHE_CONTROL).");
  gov->require_subcommand(1);
  { std::string* co = sref(); std::string* kind = sref(); std::string* target = sref();
    auto* c = gov->add_subcommand("vote", "Vote to add or remove a validator");
    c->add_option("kind", *kind, "add | remove")->required()->check(CLI::IsMember({"add", "remove"}));
    c->add_option("pubkey", *target, "Target validator pubkey (64 hex or @name)")->required();
    c->add_option("--morphe-control,--control", *co, "The Morphe node's control address: host:port of its JSON-RPC control port (control_port). Env TECHNE_MORPHE_CONTROL.");
    c->callback([&rc, co, kind, target] {
      rc = control_rpc(parse_endpoint(*co, "TECHNE_MORPHE_CONTROL", "morphe-control"), "admin.gov_vote",
                       "{\"kind\":\"" + *kind + "\",\"target\":\"" + resolve_pubkey(*target) + "\"}"); }); }

  auto* snap = app.add_subcommand("snapshot", "Dump/load node state via the control port");
  snap->footer("Endpoint: `--morphe-control host:port` (or set TECHNE_MORPHE_CONTROL).");
  snap->require_subcommand(1);
  for (const char* action : {"dump", "load"}) {
    std::string* co = sref(); std::string* path = sref();
    std::string method = std::string("admin.snapshot_") + action;
    auto* c = snap->add_subcommand(action, std::string(action) == "dump" ? "Write node state to a file"
                                                                          : "Load node state from a file");
    c->add_option("path", *path, "Snapshot file path (on the node's host)")->required();
    c->add_option("--morphe-control,--control", *co, "The Morphe node's control address: host:port of its JSON-RPC control port (control_port). Env TECHNE_MORPHE_CONTROL.");
    c->callback([&rc, co, path, method] {
      rc = control_rpc(parse_endpoint(*co, "TECHNE_MORPHE_CONTROL", "morphe-control"), method,
                       "{\"path\":\"" + *path + "\"}"); }); }

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
  return rc;
}
