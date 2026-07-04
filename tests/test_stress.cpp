#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <hyle/core/crypto.h>

#include <vector>

using namespace hyle;

namespace {

void assert_agreement(LocalCluster& c, int upto, uint64_t height) {
  Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 0; i < upto; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() >= height);
    BOOST_TEST((c.nodes[i]->composite_hash() == h0));
  }
}

} // namespace

BOOST_AUTO_TEST_SUITE(StressTests)

BOOST_AUTO_TEST_CASE(ScaleConvergesManyNodes) {
  const int N = 24;
  const uint64_t H = 4;
  std::vector<MockStateMachine> sms(N);
  std::vector<StateMachine*> ptrs;
  for (auto& s : sms) ptrs.push_back(&s);
  LocalCluster c(ptrs);
  c.run(H, N);
  assert_agreement(c, N, H);
  for (uint64_t h = 1; h <= H; h++)
    for (int i = 1; i < N; i++)
      BOOST_TEST((sms[i].applied.at(h - 1) == sms[0].applied.at(h - 1)));
}

BOOST_AUTO_TEST_CASE(ToleratesUpToFCrashFaults) {
  const int N = 10;
  const int f = 3;
  std::vector<MockStateMachine> sms(N);
  std::vector<StateMachine*> ptrs;
  for (auto& s : sms) ptrs.push_back(&s);
  LocalCluster c(ptrs);
  for (int i = 0; i < f; i++) c.deactivate(N - 1 - i);
  c.run(5, N - f);
  assert_agreement(c, N - f, 5);
}

BOOST_AUTO_TEST_CASE(StallsBelowQuorum) {
  const int N = 10;
  const int down = 4;
  std::vector<MockStateMachine> sms(N);
  std::vector<StateMachine*> ptrs;
  for (auto& s : sms) ptrs.push_back(&s);
  LocalCluster c(ptrs);
  for (int i = 0; i < down; i++) c.deactivate(N - 1 - i);
  c.run(3, N - down, /*max_ticks=*/1500);
  for (int i = 0; i < N - down; i++) BOOST_TEST(c.nodes[i]->last_decided() == 0u);
}

BOOST_AUTO_TEST_SUITE_END()
