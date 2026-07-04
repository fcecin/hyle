#include <boost/test/unit_test.hpp>

#include "mock_state_machine.h"
#include "sim_cluster.h"

#include <hyle/core/crypto.h>

#include <vector>

using namespace hyle;

namespace {

std::vector<StateMachine*> ptrs_of(std::vector<MockStateMachine>& sms) {
  std::vector<StateMachine*> p;
  for (auto& s : sms) p.push_back(&s);
  return p;
}

void assert_safe(const std::vector<MockStateMachine>& sms, uint64_t goal) {
  for (uint64_t h = 1; h <= goal; h++) {
    const wire::Bytes* ref = nullptr;
    for (const auto& s : sms)
      if (s.applied.size() >= h) {
        if (!ref) ref = &s.applied[h - 1];
        else BOOST_TEST((s.applied[h - 1] == *ref));
      }
  }
}

SimConfig async_cfg(uint64_t seed, uint32_t max_delay, uint32_t dup_pct) {
  SimConfig c;
  c.seed = seed;
  c.loss_pct = 0;
  c.max_delay = max_delay;
  c.dup_pct = dup_pct;
  c.gst_tick = ~0ull;
  return c;
}

SimConfig lossy_cfg(uint64_t seed, uint32_t loss_pct, uint32_t max_delay, uint32_t dup_pct,
                    uint64_t gst_tick) {
  SimConfig c;
  c.seed = seed;
  c.loss_pct = loss_pct;
  c.max_delay = max_delay;
  c.dup_pct = dup_pct;
  c.gst_tick = gst_tick;
  return c;
}

} // namespace

BOOST_AUTO_TEST_SUITE(SimTests)

BOOST_AUTO_TEST_CASE(ReliableConverges) {
  const int N = 10;
  const uint64_t H = 5;
  std::vector<MockStateMachine> sms(N);
  SimCluster c(ptrs_of(sms), SimConfig{});
  BOOST_REQUIRE(c.run(H, N));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(DelayedReorderedDuplicatedConverges) {
  const int N = 10;
  const uint64_t H = 5;
  std::vector<MockStateMachine> sms(N);
  SimCluster c(ptrs_of(sms), async_cfg(12345, /*max_delay=*/6, /*dup_pct=*/20));
  BOOST_REQUIRE(c.run(H, N));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
  BOOST_TEST(c.duped > 0u);
}

BOOST_AUTO_TEST_CASE(ByzantineProposerRejectedChainProgresses) {
  const int N = 10;
  const uint64_t H = 10;
  std::vector<MockStateMachine> sms(N);
  SimCluster c(ptrs_of(sms), async_cfg(2, /*max_delay=*/4, /*dup_pct=*/0));
  c.set_role(N - 1, Byz::BadPropose);
  BOOST_REQUIRE(c.run(H, N));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
  BOOST_TEST(c.byz_props > 0u);
}

BOOST_AUTO_TEST_CASE(EquivocatingProposerStaysSafe) {
  const int N = 10;
  const uint64_t H = 10;
  std::vector<MockStateMachine> sms(N);
  SimCluster c(ptrs_of(sms), async_cfg(777, /*max_delay=*/4, /*dup_pct=*/0));
  c.set_role(N - 1, Byz::Equivocate);
  BOOST_REQUIRE(c.run(H, N));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
  BOOST_TEST(c.byz_props > 0u);
  BOOST_TEST(c.split > 0u);
}

BOOST_AUTO_TEST_CASE(NilVotingMinorityTolerated) {
  const int N = 10;
  const int f = 3;
  const uint64_t H = 5;
  std::vector<MockStateMachine> sms(N);
  for (int i = N - f; i < N; i++) sms[i].accept = false;
  SimCluster c(ptrs_of(sms), async_cfg(1, /*max_delay=*/4, /*dup_pct=*/0));
  BOOST_REQUIRE(c.run(H, N));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(LossyNetworkConvergesViaBlockSync) {
  const int N = 10;
  const uint64_t H = 5;
  std::vector<MockStateMachine> sms(N);
  SimCluster c(ptrs_of(sms), lossy_cfg(9, /*loss_pct=*/25, /*max_delay=*/5, /*dup_pct=*/10,
                                       /*gst_tick=*/400));
  BOOST_REQUIRE(c.run(H, N));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
  BOOST_TEST(c.dropped > 0u);
  BOOST_TEST(c.duped > 0u);
}

BOOST_AUTO_TEST_CASE(KitchenSink200Nodes) {
  const int N = 200;
  const uint64_t H = 2;
  const int silent = 8;
  std::vector<MockStateMachine> sms(N);
  for (int i = 180; i < 190; i++) sms[i].accept = false;
  SimCluster c(ptrs_of(sms), async_cfg(2024, /*max_delay=*/3, /*dup_pct=*/5));
  c.set_role(0, Byz::BadPropose);
  c.set_role(1, Byz::Equivocate);
  for (int i = 190; i < 198; i++) c.deactivate(i);
  BOOST_REQUIRE(c.run(H, N - silent, /*max_events=*/3000000));
  assert_safe(sms, H);
  BOOST_TEST(c.all_agree());
  BOOST_TEST(c.byz_props > 0u);
  BOOST_TEST(c.duped > 0u);
}

BOOST_AUTO_TEST_SUITE_END()
