#include <hyle/morphe/asio_mesh.h>
#include <hyle/morphe/client_rest.h>
#include <hyle/morphe/frame.h>
#include <hyle/services/genesis.h>
#include <hyle/services/hex.h>
#include <hyle/services/keys.h>
#include <hyle/morphe/manual.h>
#include <hyle/services/ops.h>
#include <hyle/morphe/rpc.h>
#include <hyle/morphe/rpc_server.h>
#include <hyle/services/runtime.h>
#include <hyle/services/schema.h>
#include <hyle/morphe/testnet.h>

#include <CLI/CLI.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <set>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace hyle;

namespace {

std::string read_file(const std::string& path) {
  std::ifstream f(path);
  if (!f) throw std::runtime_error("cannot read " + path);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}
void write_file(const std::string& path, const std::string& content) {
  std::ofstream f(path, std::ios::trunc);
  if (!f) throw std::runtime_error("cannot write " + path);
  f << content;
}

std::string to_hex_str(const uint8_t* p, size_t n) { return services::hex_encode(p, n); }

void jlog(const char* level, const char* event, const std::string& data) {
  char ts[32];
  std::time_t t = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  gmtime_s(&tm, &t);
#else
  gmtime_r(&t, &tm);
#endif
  std::strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%SZ", &tm);
  std::printf("{\"timestamp\":\"%s\",\"level\":\"%s\",\"event\":\"%s\",\"data\":%s}\n", ts, level,
              event, data.c_str());
  std::fflush(stdout);
}

std::string http_post_local(uint16_t port, const std::string& json_body) {
  namespace beast = boost::beast;
  namespace http = beast::http;
  using tcp = boost::asio::ip::tcp;
  boost::asio::io_context io;
  tcp::socket sock(io);
  sock.connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));
  http::request<http::string_body> req(http::verb::post, "/", 11);
  req.set(http::field::host, "localhost");
  req.set(http::field::content_type, "application/json");
  req.body() = json_body;
  req.prepare_payload();
  http::write(sock, req);
  beast::flat_buffer b;
  http::response<http::string_body> res;
  http::read(sock, b, res);
  beast::error_code ec;
  sock.shutdown(tcp::socket::shutdown_both, ec);
  return res.body();
}

std::string default_home() {
  const char* e = std::getenv("MORPHE_HOME");
  return (e && *e) ? std::string(e) : std::string("morphe-home");
}

std::string g_exe;
std::vector<pid_t> g_children;
volatile std::sig_atomic_t g_stop = 0;
void on_stop_signal(int) { g_stop = 1; }

int do_man(const std::string& topic) {
  if (topic.empty()) {
    std::printf("MORPHE MANUAL -- the whole system, in the binary. Run: morphe man <topic>\n\n");
    for (const auto& t : morphe::manual::topics())
      std::printf("  %-12s %s\n", t.first.c_str(), t.second.c_str());
    std::printf("\n  all          print every topic (pipe to a file or feed an agent the whole manual)\n");
    std::printf("\nAlso: `morphe --help`, `morphe <cmd> --help`, `morphe --help-all`.\n");
    return 0;
  }
  if (topic == "all") {
    for (const auto& t : morphe::manual::topics())
      if (const std::string* text = morphe::manual::lookup(t.first)) std::printf("%s\n\n", text->c_str());
    return 0;
  }
  const std::string* text = morphe::manual::lookup(topic);
  if (!text) {
    std::fprintf(stderr, "unknown manual topic '%s'. run `morphe man` for the list.\n", topic.c_str());
    return 1;
  }
  std::printf("%s\n", text->c_str());
  return 0;
}

int do_pubkey(const std::string& home) {
  const KeyPair key = services::load_key(home + "/node.key");
  std::printf("%s\n", services::pubkey_hex(key.pub).c_str());
  return 0;
}

int do_keygen(const std::string& out) {
  const KeyPair kp = KeyPair::generate();
  services::save_key(out, kp);
  std::printf("wrote key %s\npubkey %s\n", out.c_str(), services::pubkey_hex(kp.pub).c_str());
  return 0;
}

int do_init(const std::string& home) {
  fs::create_directories(home);
  const KeyPair kp = KeyPair::generate();
  services::save_key(home + "/node.key", kp);
  services::Genesis g;
  g.chain_id = "morphe-devnet";
  g.validators = {kp.pub};
  g.allocations = {{kp.pub, 1000000}};
  write_file(home + "/genesis.txt", g.to_text());
  write_file(home + "/config.txt", "block_pace_ms 1000\ncontrol_port 46000\nclient_port 47000\n");
  std::printf("initialized %s (solo)\n  chain_id %s\n  validator %s\n  genesis_hash %s\n"
              "  control_port 46000  client_port 47000\n",
              home.c_str(), g.chain_id.c_str(), services::pubkey_hex(kp.pub).c_str(),
              services::pubkey_hex(g.hash()).c_str());
  return 0;
}

int do_testnet(int n, const std::string& dir, uint16_t base_port) {
  const services::Genesis g = morphe::generate_testnet(dir, n, base_port);
  std::printf("generated %d-validator testnet in %s\n  chain_id %s\n  genesis_hash %s\n", n,
              dir.c_str(), g.chain_id.c_str(), services::pubkey_hex(g.hash()).c_str());
  for (int i = 0; i < n; ++i)
    std::printf("  node%d: port %u  (morphe start %s/node%d)\n", i,
                static_cast<unsigned>(base_port + i), dir.c_str(), i);
  return 0;
}

int do_genesis(const std::string& sub, const std::string& path) {
  const services::Genesis g = services::Genesis::parse(read_file(path));
  if (sub == "hash") { std::printf("%s\n", services::pubkey_hex(g.hash()).c_str()); return 0; }
  std::string err;
  if (g.validate(err)) {
    std::printf("ok: %zu validators, chain '%s'\n", g.validators.size(), g.chain_id.c_str());
    return 0;
  }
  std::fprintf(stderr, "invalid: %s\n", err.c_str());
  return 1;
}

struct Driver {
  boost::asio::io_context& io;
  services::Runtime& rt;
  boost::asio::steady_timer timer;
  uint64_t pace_ms;
  int idle = 0;
  uint64_t last_h = 0;
  size_t last_peers = ~size_t(0);
  std::chrono::steady_clock::time_point last_commit{};
  Driver(boost::asio::io_context& io_, services::Runtime& rt_, uint64_t pace)
      : io(io_), rt(rt_), timer(io_), pace_ms(pace) {}
  void tick() {
    bool prog = rt.pump();
    const bool pending = rt.app().mempool().size() > 0;
    const auto now = std::chrono::steady_clock::now();
    const bool paced =
        std::chrono::duration_cast<std::chrono::milliseconds>(now - last_commit).count() >=
        static_cast<long long>(pace_ms);
    if (pending || paced) prog = rt.advance() || prog;
    if (rt.height() != last_h) { last_h = rt.height(); last_commit = now; }
    if (rt.peer_count() != last_peers) {
      last_peers = rt.peer_count();
      jlog("info", "peers_changed", "{\"count\":" + std::to_string(last_peers) + "}");
    }
    if (!prog) { if (++idle > 200) { rt.fire_one_timeout(); idle = 0; } }
    else idle = 0;
    timer.expires_after(std::chrono::milliseconds(5));
    timer.async_wait([this](const boost::system::error_code& ec) { if (!ec) tick(); });
  }
};

int do_start(const std::string& home) {
  const services::Genesis g = services::Genesis::parse(read_file(home + "/genesis.txt"));
  const KeyPair key = services::load_key(home + "/node.key");
  std::string err;
  if (!g.validate(err)) { std::fprintf(stderr, "bad genesis: %s\n", err.c_str()); return 1; }
  const uint64_t pace = morphe::read_config_u64(home, "block_pace_ms", 1000);
  const std::vector<morphe::TestnetPeer> peers = morphe::parse_peers(home);
  const bool solo = peers.empty();

  boost::asio::io_context io;
  std::optional<morphe::AsioMesh> mesh;
  std::optional<services::Runtime> rt_opt;
  if (solo) {
    rt_opt.emplace(g, key, pace);
  } else {
    const uint16_t listen_port = static_cast<uint16_t>(morphe::read_config_u64(home, "listen_port", 0));
    const uint32_t tag = morphe::chain_tag_of(
        wire::View(reinterpret_cast<const uint8_t*>(g.chain_id.data()), g.chain_id.size()));
    mesh.emplace(io, key, tag, listen_port);
    for (const auto& p : peers) mesh->add_peer(p.pk, p.host, p.port);
    rt_opt.emplace(g, key, pace, &*mesh);
    fs::create_directories(home + "/evidence");
    rt_opt->set_evidence_dir(home + "/evidence");
  }
  services::Runtime& rt = *rt_opt;

  rt.app().add_on_commit([](const services::CommitEvent& e) {
    size_t applied = 0;
    for (const auto& t : e.txs) if (t.second) ++applied;
    jlog("info", "block_decided",
         "{\"height\":" + std::to_string(e.height) + ",\"txs\":" + std::to_string(e.txs.size()) +
             ",\"applied\":" + std::to_string(applied) + "}");
    for (const auto& t : e.txs)
      if (t.second)
        jlog("info", "tx_committed", "{\"tx_id\":\"" + to_hex_str(t.first.data(), t.first.size()) +
                                         "\",\"height\":" + std::to_string(e.height) + "}");
  });

  jlog("info", "node_start",
       "{\"chain\":\"" + g.chain_id + "\",\"genesis\":\"" + services::pubkey_hex(g.hash()) +
           "\",\"mode\":\"" + (solo ? "solo" : "mesh") + "\",\"peers\":" + std::to_string(peers.size()) +
           "}");

  const uint16_t control_port = static_cast<uint16_t>(morphe::read_config_u64(home, "control_port", 0));
  const uint16_t client_port = static_cast<uint16_t>(morphe::read_config_u64(home, "client_port", 0));
  std::optional<morphe::RpcService> svc;
  std::optional<morphe::RpcHttpServer> ctrl;
  std::optional<morphe::ClientRestServer> client;
  if (control_port != 0 || client_port != 0) svc.emplace(rt);
  if (control_port != 0) {
    ctrl.emplace(io, *svc, control_port, "127.0.0.1");
    ctrl->start();
    ctrl->attach_events();
    jlog("info", "control_listen", "{\"port\":" + std::to_string(ctrl->port()) + "}");
  }
  if (client_port != 0) {
    const std::string bind = morphe::read_config_str(home, "client_bind", "0.0.0.0");
    client.emplace(io, *svc, client_port, bind);
    client->start();
    jlog("info", "client_listen", "{\"port\":" + std::to_string(client->port()) + ",\"bind\":\"" + bind + "\"}");
  }
  std::fflush(stdout);

  if (mesh) mesh->start();
  rt.begin();
  rt.set_shutdown_hook([&io] { boost::asio::post(io, [&io] { io.stop(); }); });
  Driver driver(io, rt, pace);
  driver.tick();
  io.run();
  return 0;
}

int do_up(const std::string& dir) {
  std::vector<std::string> homes;
  if (fs::is_directory(dir))
    for (const auto& e : fs::directory_iterator(dir))
      if (e.is_directory() && fs::exists(e.path() / "config.txt") && fs::exists(e.path() / "genesis.txt"))
        homes.push_back(e.path().string());
  std::sort(homes.begin(), homes.end());
  if (homes.empty()) {
    std::fprintf(stderr, "no node homes (dir with config.txt + genesis.txt) under %s\n", dir.c_str());
    return 1;
  }

  g_children.clear();
  for (const std::string& h : homes) {
    const pid_t pid = ::fork();
    if (pid < 0) { std::fprintf(stderr, "fork failed for %s\n", h.c_str()); continue; }
    if (pid == 0) {
      const std::string log = h + "/node.log";
      const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) { ::dup2(fd, 1); ::dup2(fd, 2); ::close(fd); }
      ::execl(g_exe.c_str(), "morphe", "start", h.c_str(), static_cast<char*>(nullptr));
      _exit(127);
    }
    g_children.push_back(pid);
    std::printf("started %s  pid %d  log %s/node.log\n", h.c_str(), static_cast<int>(pid), h.c_str());
  }
  std::printf("\n%zu node(s) up. Ctrl-C stops all. Watch a node: tail -f %s/node.log\n",
              g_children.size(), homes.front().c_str());
  std::fflush(stdout);

  std::signal(SIGINT, on_stop_signal);
  std::signal(SIGTERM, on_stop_signal);
  // only ever signal live children: a reaped pid may be recycled to an unrelated process.
  std::set<pid_t> alive(g_children.begin(), g_children.end());
  while (!g_stop && !alive.empty()) {
    int status = 0;
    const pid_t r = ::waitpid(-1, &status, WNOHANG);
    if (r > 0) { alive.erase(r); std::fprintf(stderr, "node pid %d exited\n", static_cast<int>(r)); }
    else { const timespec ts{0, 100 * 1000 * 1000}; ::nanosleep(&ts, nullptr); }
  }
  for (const pid_t p : alive) ::kill(p, SIGTERM);
  for (size_t i = 0; i < alive.size(); ++i) { int st = 0; ::waitpid(-1, &st, 0); }
  std::printf("all nodes stopped\n");
  return 0;
}

int do_config(const std::string& home) {
  std::printf("home          %s\n", home.c_str());
  std::printf("node.key      %s\n", fs::exists(home + "/node.key") ? "present" : "MISSING");
  if (fs::exists(home + "/genesis.txt")) {
    try {
      const services::Genesis g = services::Genesis::parse(read_file(home + "/genesis.txt"));
      std::printf("chain_id      %s\n", g.chain_id.c_str());
      std::printf("genesis_hash  %s\n", services::pubkey_hex(g.hash()).c_str());
      std::printf("validators    %zu\n", g.validators.size());
    } catch (const std::exception& e) { std::printf("genesis.txt   INVALID: %s\n", e.what()); }
  } else {
    std::printf("genesis.txt   MISSING\n");
  }
  std::printf("block_pace_ms %llu\n",
              static_cast<unsigned long long>(morphe::read_config_u64(home, "block_pace_ms", 1000)));
  const uint64_t lp = morphe::read_config_u64(home, "listen_port", 0);
  const uint64_t cp = morphe::read_config_u64(home, "control_port", 0);
  const uint64_t clp = morphe::read_config_u64(home, "client_port", 0);
  std::printf("listen_port   %s\n", lp ? std::to_string(lp).c_str() : "(unset -> solo, no mesh)");
  std::printf("control_port  %s\n", cp ? std::to_string(cp).c_str() : "(unset -> no control RPC)");
  std::printf("client_port   %s\n", clp ? std::to_string(clp).c_str() : "(unset -> no client REST)");
  std::printf("peers         %zu\n", morphe::parse_peers(home).size());
  return 0;
}

int do_doctor(const std::string& home) {
  auto line = [](const char* tag, const std::string& msg) { std::printf("  [%s] %s\n", tag, msg.c_str()); };
  auto height_of = [](const std::string& s) -> long long {
    const auto p = s.find("\"height\":");
    return p == std::string::npos ? -1 : std::atoll(s.c_str() + p + 9);
  };
  std::printf("morphe doctor: %s\n", home.c_str());
  if (!fs::is_directory(home)) { line("FAIL", "home directory does not exist"); return 1; }

  int fails = 0;
  std::string mypk;
  try {
    const KeyPair k = services::load_key(home + "/node.key");
    mypk = services::pubkey_hex(k.pub);
    line("ok", "node.key loads; identity " + mypk);
  } catch (const std::exception& e) { line("FAIL", std::string("node.key: ") + e.what()); ++fails; }

  try {
    const services::Genesis g = services::Genesis::parse(read_file(home + "/genesis.txt"));
    std::string err;
    if (!g.validate(err)) { line("FAIL", "genesis invalid: " + err); ++fails; }
    else {
      bool mine = false;
      for (const auto& v : g.validators) if (services::pubkey_hex(v) == mypk) mine = true;
      line("ok", "genesis valid; chain " + g.chain_id + "; " + std::to_string(g.validators.size()) +
                     " validators; this node is " + (mine ? "a genesis validator" : "NOT a genesis validator"));
    }
  } catch (const std::exception& e) { line("FAIL", std::string("genesis: ") + e.what()); ++fails; }

  const uint64_t lp = morphe::read_config_u64(home, "listen_port", 0);
  const uint64_t rp = morphe::read_config_u64(home, "control_port", 0);
  line(lp ? "ok" : "warn",
       lp ? ("listen_port " + std::to_string(lp) + "; " + std::to_string(morphe::parse_peers(home).size()) +
             " peers configured")
          : "no listen_port (solo mode, no mesh)");

  if (rp == 0) { line("warn", "no control_port; cannot probe the running node"); }
  else {
    const std::string body = "{\"jsonrpc\":\"2.0\",\"method\":\"status\",\"params\":{},\"id\":1}";
    try {
      const long long h1 = height_of(http_post_local(static_cast<uint16_t>(rp), body));
      if (h1 < 0) { line("FAIL", "control RPC replied but no height field"); ++fails; }
      else {
        line("ok", "control RPC reachable on port " + std::to_string(rp) + "; height " + std::to_string(h1));
        const timespec ts{1, 500 * 1000 * 1000};
        ::nanosleep(&ts, nullptr);
        const long long h2 = height_of(http_post_local(static_cast<uint16_t>(rp), body));
        line(h2 > h1 ? "ok" : "warn",
             h2 > h1 ? ("height advancing (" + std::to_string(h1) + " -> " + std::to_string(h2) + ")")
                     : ("height NOT advancing (stuck at " + std::to_string(h1) + "?)"));
      }
    } catch (const std::exception&) {
      line("warn", "node not reachable on control_port " + std::to_string(rp) + " (is it running?)");
    }
  }
  std::printf("%s\n", fails ? "doctor: problems found" : "doctor: ok");
  return fails ? 1 : 0;
}

}  // namespace

int main(int argc, char** argv) {
  { char buf[4096]; const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n > 0) { buf[n] = '\0'; g_exe = buf; } else if (argc > 0) g_exe = argv[0]; }

  CLI::App app{"Morphe -- an in-RAM BFT KV blockchain node (Hyle layer 3).", "morphe"};
  app.require_subcommand(1);
  app.set_version_flag("--version", "morphe 0.0.0 (Hyle layer 3)");
  app.set_help_all_flag("--help-all", "Show help for every subcommand");
  app.footer(
      "The whole system is documented inside this binary. Run `morphe man` to list the manual topics, "
      "`morphe man quickstart` to get a chain running, or `morphe man all` for everything. Any command "
      "self-documents: append `--help` (and `morphe --help-all` shows every subcommand at once).\n"
      "\n"
      "`morphe` is the SERVER (it runs a node). To act on a chain as a client -- submit txs, query, vote "
      "-- use the separate `techne` binary against a node's client_port (public REST) or control_port "
      "(firewalled); see `techne man`. Tip: set MORPHE_HOME to skip the <home> argument, and "
      "`morphe up <testnet-dir>` runs a whole local testnet at once.");

  int rc = 0;
  std::deque<std::string> S;  // stable storage for CLI11-bound string options (deque keeps addresses)
  auto sref = [&]() -> std::string* { S.emplace_back(); return &S.back(); };

  { std::string* topic = sref();
    auto* c = app.add_subcommand("man", "Built-in manual: run `morphe man` for topics, `man <topic>` for one");
    c->add_option("topic", *topic, "Manual topic (omit to list all)");
    c->callback([&rc, topic] { rc = do_man(*topic); }); }

  { std::string* out = sref(); *out = "node.key";
    auto* c = app.add_subcommand("keygen", "Generate an ed25519 node key");
    c->add_option("file", *out, "Output key file")->capture_default_str();
    c->callback([&rc, out] { rc = do_keygen(*out); }); }

  { std::string* home = sref(); *home = default_home();
    auto* c = app.add_subcommand("init", "Scaffold a home dir (key + genesis + config); self is the sole validator");
    c->add_option("home", *home, "Home directory to create")->capture_default_str();
    c->footer("Example: run `morphe init mychain`, then `morphe start mychain`.");
    c->callback([&rc, home] { rc = do_init(*home); }); }

  { std::string* home = sref(); *home = default_home();
    auto* c = app.add_subcommand("pubkey", "Print the public key (account / identity) of a home's node.key");
    c->alias("whoami");
    c->add_option("home", *home, "Node home directory")->capture_default_str();
    c->callback([&rc, home] { rc = do_pubkey(*home); }); }

  { std::string* dir = sref(); *dir = "morphe-testnet";
    static int n = 0; static uint16_t base = 40000;
    auto* c = app.add_subcommand("testnet", "Generate an N-validator loopback testnet (node0..nodeN-1)");
    c->add_option("n", n, "Number of validators")->required();
    c->add_option("dir", *dir, "Output directory")->capture_default_str();
    c->add_option("base_port", base, "First listen port (RPC port = base+1000+i)")->capture_default_str();
    c->footer("Example: run `morphe testnet 4 tn 40000`, then bring it up with `morphe up tn`.");
    c->callback([&rc, dir] { rc = do_testnet(n, *dir, base); }); }

  { std::string* home = sref(); *home = default_home();
    auto* c = app.add_subcommand("start", "Run the node from a home dir (mesh if peers.txt present, else solo)");
    c->add_option("home", *home, "Node home directory")->capture_default_str();
    c->callback([&rc, home] { rc = do_start(*home); }); }

  { std::string* dir = sref(); *dir = "morphe-testnet";
    auto* c = app.add_subcommand("up", "Start and supervise every node under a testnet dir; Ctrl-C stops all");
    c->add_option("dir", *dir, "Testnet directory (holds node0..nodeN-1)")->capture_default_str();
    c->footer("Example: `morphe testnet 4 tn 40000` scaffolds a testnet; `morphe up tn` runs it.");
    c->callback([&rc, dir] { rc = do_up(*dir); }); }

  { std::string* home = sref(); *home = default_home();
    auto* c = app.add_subcommand("config", "Print a home's effective config (ports, pace, genesis, peers)");
    c->add_option("home", *home, "Node home directory")->capture_default_str();
    c->callback([&rc, home] { rc = do_config(*home); }); }

  { std::string* home = sref(); *home = default_home();
    auto* c = app.add_subcommand("doctor", "Diagnose a home: key, genesis, config, and (if running) RPC + liveness");
    c->add_option("home", *home, "Node home directory")->capture_default_str();
    c->callback([&rc, home] { rc = do_doctor(*home); }); }

  auto* gen = app.add_subcommand("genesis", "Local genesis-file helpers (no running node needed)");
  gen->require_subcommand(1);
  { std::string* path = sref();
    auto* c = gen->add_subcommand("validate", "Validate a genesis file");
    c->add_option("path", *path, "Path to genesis.txt")->required();
    c->callback([&rc, path] { rc = do_genesis("validate", *path); }); }
  { std::string* path = sref();
    auto* c = gen->add_subcommand("hash", "Print a genesis file's canonical hash");
    c->add_option("path", *path, "Path to genesis.txt")->required();
    c->callback([&rc, path] { rc = do_genesis("hash", *path); }); }

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    return app.exit(e);
  } catch (const std::exception& e) {
    std::string msg(e.what());
    for (char& c : msg) if (c == '"' || c == '\\') c = '\'';
    jlog("error", "error", "{\"message\":\"" + msg + "\"}");
    std::fprintf(stderr, "error: %s\n", e.what());
    return 1;
  }
  return rc;
}
