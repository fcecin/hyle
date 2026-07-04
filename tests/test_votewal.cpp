#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <filesystem>
#include <string>
#include <vector>

using namespace hyle;

namespace {

struct TempDir {
  std::filesystem::path path;
  explicit TempDir(const std::string& tag) {
    path = std::filesystem::temp_directory_path() / ("hyle_votewal_" + tag);
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
    std::filesystem::create_directories(path, ec);
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

uintmax_t wal_size(const std::filesystem::path& dir, const PubKey& pk) {
  static const char* d = "0123456789abcdef";
  std::string hex;
  for (uint8_t b : pk) {
    hex.push_back(d[b >> 4]);
    hex.push_back(d[b & 0xf]);
  }
  std::error_code ec;
  auto sz = std::filesystem::file_size(dir / ("votewal-" + hex + ".bin"), ec);
  return ec ? 0 : sz;
}

std::vector<StateMachine*> ptrs(std::vector<MockStateMachine>& sm) {
  std::vector<StateMachine*> out;
  for (auto& s : sm) out.push_back(&s);
  return out;
}

}  // namespace

BOOST_AUTO_TEST_SUITE(VoteWalTests)

BOOST_AUTO_TEST_CASE(DisabledByDefaultNoFiles) {
  TempDir tmp("disabled");
  std::vector<MockStateMachine> sm(4);
  auto sms = ptrs(sm);
  LocalCluster c(sms);
  c.run(2, 4);
  for (int i = 0; i < 4; i++) BOOST_TEST(wal_size(tmp.path, c.nodes[i]->pubkey()) == 0u);
}

BOOST_AUTO_TEST_CASE(BoundedAcrossHeights) {
  TempDir tmp("bounded");
  std::vector<MockStateMachine> sm(4);
  auto sms = ptrs(sm);
  LocalCluster c(sms, 1024, 0, -1, "", tmp.path.string());
  c.run(30, 4);
  for (int i = 0; i < 4; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() == 30u);
    BOOST_TEST(wal_size(tmp.path, c.nodes[i]->pubkey()) < 16u * 1024u);
  }
  for (uint64_t h = 1; h <= 30; h++) {
    const wire::Bytes& ref = sm[0].applied.at(h - 1);
    BOOST_REQUIRE(!ref.empty());
    for (int i = 1; i < 4; i++) BOOST_TEST((sm[i].applied.at(h - 1) == ref));
  }
}

BOOST_AUTO_TEST_CASE(CrashMidHeightReloadsAndStaysSafe) {
  TempDir tmp("crash");
  std::vector<MockStateMachine> sm(4);
  auto sms = ptrs(sm);
  LocalCluster c(sms, 1024, 0, -1, "", tmp.path.string());
  c.start(1);
  c.pump();

  const int victim = 1;
  BOOST_REQUIRE(wal_size(tmp.path, c.nodes[victim]->pubkey()) > 0u);
  BOOST_TEST(c.nodes[victim]->last_decided() == 0u);

  size_t replayed = c.crash_wal(victim);
  BOOST_TEST(replayed > 0u);

  for (int t = 0; t < 100000; t++) {
    bool prog = c.pump();
    if (c.committed(1) >= 3) break;
    if (!prog && !c.fire_one_timeout()) break;
  }
  BOOST_TEST(c.committed(1) >= 3);
  wire::Bytes ref;
  for (int i = 0; i < 4; i++)
    if (sm[i].applied.size() >= 1) {
      if (ref.empty())
        ref = sm[i].applied[0];
      else
        BOOST_TEST((sm[i].applied[0] == ref));
    }
  BOOST_REQUIRE(!ref.empty());
}

BOOST_AUTO_TEST_SUITE_END()
