
#include <boost/test/unit_test.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::string self_dir() {
  char buf[4096];
  const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
  if (n <= 0) return ".";
  buf[n] = '\0';
  return fs::path(buf).parent_path().string();
}

std::string bin_path(const char* name) {
  return (fs::path(self_dir()).parent_path() / name).string();
}

struct Result {
  int code = -1;
  std::string out;
};

Result run(const std::string& bin, const std::vector<std::string>& args) {
  int fds[2];
  if (::pipe(fds) != 0) return {};
  const pid_t pid = ::fork();
  if (pid == 0) {
    ::dup2(fds[1], 1);
    ::dup2(fds[1], 2);
    ::close(fds[0]);
    ::close(fds[1]);
    std::vector<char*> av;
    av.push_back(const_cast<char*>(bin.c_str()));
    for (const auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
    av.push_back(nullptr);
    ::execv(bin.c_str(), av.data());
    _exit(127);
  }
  ::close(fds[1]);
  std::string out;
  char buf[4096];
  ssize_t n;
  while ((n = ::read(fds[0], buf, sizeof buf)) > 0) out.append(buf, static_cast<size_t>(n));
  ::close(fds[0]);
  int st = 0;
  ::waitpid(pid, &st, 0);
  return {WIFEXITED(st) ? WEXITSTATUS(st) : -1, out};
}

struct Node {
  pid_t pid = -1;
  void start(const std::string& bin, const std::vector<std::string>& args, const std::string& log) {
    pid = ::fork();
    if (pid == 0) {
      const int fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (fd >= 0) { ::dup2(fd, 1); ::dup2(fd, 2); ::close(fd); }
      std::vector<char*> av;
      av.push_back(const_cast<char*>(bin.c_str()));
      for (const auto& a : args) av.push_back(const_cast<char*>(a.c_str()));
      av.push_back(nullptr);
      ::execv(bin.c_str(), av.data());
      _exit(127);
    }
  }
  void stop() {
    if (pid > 0) { ::kill(pid, SIGTERM); int st = 0; ::waitpid(pid, &st, 0); pid = -1; }
  }
  ~Node() { stop(); }
};

void sleep_ms(int ms) {
  const timespec ts{ms / 1000, (ms % 1000) * 1000 * 1000};
  ::nanosleep(&ts, nullptr);
}

long json_int(const std::string& s, const std::string& key) {
  const auto p = s.find("\"" + key + "\":");
  if (p == std::string::npos) return -1;
  return std::strtol(s.c_str() + p + key.size() + 3, nullptr, 10);
}

bool port_free(int port) {
  const int s = ::socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return false;
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(static_cast<uint16_t>(port));
  a.sin_addr.s_addr = ::inet_addr("127.0.0.1");
  const bool ok = ::bind(s, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0;
  ::close(s);
  return ok;
}

int next_base() {
  static int b = 30000 + (static_cast<int>(::getpid()) % 60) * 100;
  for (int tries = 0; tries < 300; ++tries) {
    const int base = b;
    b += 100;
    bool ok = true;
    for (int off : {0, 1, 2, 3, 1000, 1001, 1002, 1003, 2000, 2001, 2002, 2003})
      if (!port_free(base + off)) { ok = false; break; }
    if (ok) return base;
  }
  return b;
}

void append_endpoint(std::vector<std::string>& out, const std::vector<std::string>& cmdargs,
                     const std::string& node_ep, const std::string& ctrl_ep) {
  const std::string cmd = cmdargs.empty() ? "" : cmdargs[0];
  const std::string sub = cmdargs.size() > 1 ? cmdargs[1] : "";
  auto is_control_query = [&](const std::string& s) {
    return s == "validators" || s == "apphash" || s == "status" || s == "mempool" || s == "governance";
  };
  if (cmd == "tx") { out.push_back("--node"); out.push_back(node_ep); }
  else if (cmd == "query") {
    if (is_control_query(sub)) { out.push_back("--control"); out.push_back(ctrl_ep); }
    else { out.push_back("--node"); out.push_back(node_ep); }
  } else if (cmd == "gov" || cmd == "snapshot") { out.push_back("--control"); out.push_back(ctrl_ep); }
}

Result techne_run(const std::string& techne, const std::string& keys, const std::string& node_ep,
                  const std::string& ctrl_ep, std::vector<std::string> args) {
  std::vector<std::string> a = {"--keys", keys};
  a.insert(a.end(), args.begin(), args.end());
  append_endpoint(a, args, node_ep, ctrl_ep);
  return run(techne, a);
}

struct Cluster {
  std::string morphe, techne, ws, tn, keys;
  int base;
  std::vector<std::unique_ptr<Node>> nodes;

  explicit Cluster(int n) {
    morphe = bin_path("morphe");
    techne = bin_path("techne");
    BOOST_REQUIRE_MESSAGE(fs::exists(morphe), "morphe binary not found: " << morphe);
    BOOST_REQUIRE_MESSAGE(fs::exists(techne), "techne binary not found: " << techne);
    base = next_base();
    ws = "/tmp/morphe_e2e_" + std::to_string(::getpid()) + "_" + std::to_string(base);
    fs::remove_all(ws);
    fs::create_directories(ws);
    tn = ws + "/tn";
    keys = ws + "/keys";

    const Result gen = run(morphe, {"testnet", std::to_string(n), tn, std::to_string(base)});
    BOOST_REQUIRE_MESSAGE(gen.code == 0, "testnet scaffold failed: " << gen.out);
    for (int i = 0; i < n; ++i) {
      auto node = std::make_unique<Node>();
      node->start(morphe, {"start", tn + "/node" + std::to_string(i)},
                  ws + "/node" + std::to_string(i) + ".log");
      nodes.push_back(std::move(node));
    }
    BOOST_REQUIRE_MESSAGE(wait_live(), "chain never reached height > 0 through the client port");
  }
  ~Cluster() { nodes.clear(); fs::remove_all(ws); }

  std::string node_ep() const { return "127.0.0.1:" + std::to_string(base + 2000); }
  std::string control_ep(int i) const { return "127.0.0.1:" + std::to_string(base + 1000 + i); }
  Result tc(const std::vector<std::string>& args) const {
    return techne_run(techne, keys, node_ep(), control_ep(0), args);
  }
  std::string node_key(int i) const { return tn + "/node" + std::to_string(i) + "/node.key"; }
  long height() const { return json_int(tc({"query", "height"}).out, "height"); }

  bool wait_live() {
    for (int i = 0; i < 200; ++i) { if (height() > 0) return true; sleep_ms(100); }
    return false;
  }
  bool wait_balance(const std::string& who, long amount) {
    for (int i = 0; i < 200; ++i) {
      if (json_int(tc({"query", "balance", who}).out, "balance") == amount) return true;
      sleep_ms(100);
    }
    return false;
  }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(MorpheE2E)

BOOST_AUTO_TEST_CASE(TechneFundsAndReadsIdentity) {
  Cluster c(3);
  BOOST_REQUIRE(c.tc({"key", "gen", "alice"}).code == 0);
  BOOST_TEST(json_int(c.tc({"query", "balance", "@alice"}).out, "balance") == 0);

  const Result tx = c.tc({"tx", "transfer", "--key", c.node_key(0), "@alice", "250"});
  BOOST_REQUIRE_MESSAGE(tx.out.find("\"accepted\":true") != std::string::npos,
                        "transfer not accepted: " << tx.out);
  BOOST_TEST(c.wait_balance("@alice", 250));
  BOOST_TEST(c.tc({"query", "account", "@alice"}).out.find("\"exists\":true") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(QueryReflectsGenesisAlloc) {
  Cluster c(3);
  const std::string node0_pub = c.tc({"query", "account", "@" + c.tn + "/node0"}).out;
  BOOST_TEST(node0_pub.find("\"exists\":true") != std::string::npos);
  BOOST_TEST(json_int(node0_pub, "balance") > 0);
}

BOOST_AUTO_TEST_CASE(EntryPutAndRead) {
  Cluster c(3);
  const Result put = c.tc({"tx", "entry-put", "--key", c.node_key(0), "6162", "100", "beef"});
  BOOST_REQUIRE_MESSAGE(put.out.find("\"accepted\":true") != std::string::npos,
                        "entry-put not accepted: " << put.out);
  bool seen = false;
  for (int i = 0; i < 200 && !seen; ++i) {
    const Result e = c.tc({"query", "entry", "6162"});
    seen = e.out.find("beef") != std::string::npos;
    if (!seen) sleep_ms(100);
  }
  BOOST_TEST(seen);
}

BOOST_AUTO_TEST_CASE(UnderfundedTransferRejected) {
  Cluster c(3);
  BOOST_REQUIRE(c.tc({"key", "gen", "alice"}).code == 0);
  BOOST_REQUIRE(c.tc({"tx", "transfer", "--key", c.node_key(0), "@alice", "250"}).out.find(
                    "\"accepted\":true") != std::string::npos);
  BOOST_REQUIRE(c.wait_balance("@alice", 250));

  const Result over = c.tc({"tx", "transfer", "--key", "alice", "@alice", "1000000"});
  BOOST_TEST(over.out.find("\"accepted\":false") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(GovVoteOverControlPort) {
  Cluster c(3);
  BOOST_REQUIRE(c.tc({"key", "gen", "newval"}).code == 0);
  const long before = json_int(c.tc({"query", "validators"}).out, "count");
  BOOST_TEST(before == 3);

  const Result vote = c.tc({"gov", "vote", "add", "@newval"});
  BOOST_TEST(vote.out.find("\"ok\":true") != std::string::npos);

  sleep_ms(1500);
  BOOST_TEST(json_int(c.tc({"query", "validators"}).out, "count") == 3);
}

BOOST_AUTO_TEST_CASE(ChainToleratesOneFault) {
  Cluster c(4);
  const long h0 = c.height();
  c.nodes.back()->stop();

  bool advanced = false;
  for (int i = 0; i < 200 && !advanced; ++i) {
    if (c.height() > h0 + 2) advanced = true;
    else sleep_ms(100);
  }
  BOOST_TEST(advanced);

  BOOST_REQUIRE(c.tc({"key", "gen", "carol"}).code == 0);
  BOOST_REQUIRE(c.tc({"tx", "transfer", "--key", c.node_key(0), "@carol", "70"}).out.find(
                    "\"accepted\":true") != std::string::npos);
  BOOST_TEST(c.wait_balance("@carol", 70));
}

BOOST_AUTO_TEST_CASE(ManyClientsTransact) {
  const int n = 12;

  Cluster c(3);
  BOOST_REQUIRE(c.tc({"key", "gen", "sink"}).code == 0);

  for (int i = 0; i < n; ++i) {
    const std::string who = "@cli" + std::to_string(i);
    BOOST_REQUIRE(c.tc({"key", "gen", "cli" + std::to_string(i)}).code == 0);
    const Result f = c.tc({"tx", "transfer", "--key", c.node_key(0), who, "100"});
    BOOST_REQUIRE_MESSAGE(f.out.find("\"accepted\":true") != std::string::npos,
                          "fund cli" << i << " rejected: " << f.out);
    BOOST_REQUIRE_MESSAGE(c.wait_balance(who, 100), "cli" << i << " never funded");
  }

  for (int i = 0; i < n; ++i) {
    const Result s = c.tc({"tx", "transfer", "--key", "cli" + std::to_string(i), "@sink", "50"});
    BOOST_REQUIRE_MESSAGE(s.out.find("\"accepted\":true") != std::string::npos,
                          "cli" << i << " send rejected: " << s.out);
  }
  BOOST_TEST(c.wait_balance("@sink", static_cast<long>(n) * 50));
}

BOOST_AUTO_TEST_CASE(SingleNodeDatabaseLifecycle) {
  const std::string morphe = bin_path("morphe");
  const std::string techne = bin_path("techne");
  BOOST_REQUIRE(fs::exists(morphe) && fs::exists(techne));
  const std::string ws = "/tmp/morphe_e2e_solo_" + std::to_string(::getpid());
  fs::remove_all(ws);
  fs::create_directories(ws);
  const std::string tn = ws + "/tn", snap = ws + "/db.snap", home = tn + "/node0";
  const int base = next_base();
  const std::string keys = ws + "/keys";
  const std::string node_ep = "127.0.0.1:" + std::to_string(base + 2000);
  const std::string ctrl_ep = "127.0.0.1:" + std::to_string(base + 1000);
  BOOST_REQUIRE(run(morphe, {"testnet", "1", tn, std::to_string(base)}).code == 0);

  auto tq = [&](const std::vector<std::string>& a) { return techne_run(techne, keys, node_ep, ctrl_ep, a); };
  auto wait_live = [&] { for (int i = 0; i < 200; ++i) { if (json_int(tq({"query", "height"}).out, "height") > 0) return true; sleep_ms(100); } return false; };
  auto wait_bal = [&](const std::string& who, long amt) { for (int i = 0; i < 200; ++i) { if (json_int(tq({"query", "balance", who}).out, "balance") == amt) return true; sleep_ms(100); } return false; };

  {
    Node n;
    n.start(morphe, {"start", home}, ws + "/n1.log");
    BOOST_REQUIRE_MESSAGE(wait_live(), "solo node did not serve its client port / never reached height");
    BOOST_REQUIRE(tq({"key", "gen", "alice"}).code == 0);
    BOOST_REQUIRE(tq({"tx", "transfer", "--key", home + "/node.key", "@alice", "500"}).out.find(
                      "\"accepted\":true") != std::string::npos);
    BOOST_REQUIRE_MESSAGE(wait_bal("@alice", 500), "write never committed on the solo node");
    BOOST_REQUIRE_MESSAGE(tq({"snapshot", "dump", snap}).out.find("\"ok\":true") != std::string::npos,
                          "snapshot dump failed");
    ::kill(n.pid, SIGKILL);
    int st = 0; ::waitpid(n.pid, &st, 0); n.pid = -1;
  }
  BOOST_TEST(fs::exists(snap));

  {
    Node n;
    n.start(morphe, {"start", home}, ws + "/n2.log");
    BOOST_REQUIRE(wait_live());
    BOOST_TEST(json_int(tq({"query", "balance", "@alice"}).out, "balance") == 0);
    BOOST_REQUIRE_MESSAGE(tq({"snapshot", "load", snap}).out.find("\"ok\":true") != std::string::npos,
                          "snapshot load failed");
    BOOST_TEST(wait_bal("@alice", 500));
    const long h1 = json_int(tq({"query", "height"}).out, "height");
    bool advanced = false;
    for (int i = 0; i < 100 && !advanced; ++i) {
      if (json_int(tq({"query", "height"}).out, "height") > h1) advanced = true; else sleep_ms(100);
    }
    BOOST_TEST(advanced);
  }
  fs::remove_all(ws);
}

BOOST_AUTO_TEST_SUITE_END()
