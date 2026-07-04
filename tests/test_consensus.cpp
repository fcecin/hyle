#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <hyle/core/consensus.h>
#include <hyle/core/crypto.h>
#include <hyle/services/kv/kv_state_machine.h>
#include <hyle/services/kv/ops.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

using namespace hyle;

static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

BOOST_AUTO_TEST_SUITE(ConsensusTests)

BOOST_AUTO_TEST_CASE(FourNodesAgreeEachHeight) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run(5, 4);

  for (int i = 0; i < 4; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() == 5u);
    BOOST_TEST(c.nodes[i]->decide_misses() == 0u);
  }
  for (uint64_t h = 1; h <= 5; h++) {
    const wire::Bytes& ref = sm[0].applied.at(h - 1);
    BOOST_REQUIRE(!ref.empty());
    for (int i = 1; i < 4; i++) BOOST_TEST((sm[i].applied.at(h - 1) == ref));
  }
}

BOOST_AUTO_TEST_CASE(SevenNodesAgree) {
  std::vector<MockStateMachine> sm(7);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run(2, 7);

  for (int i = 0; i < 7; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() == 2u);
    BOOST_TEST(c.nodes[i]->decide_misses() == 0u);
  }
  for (uint64_t h = 1; h <= 2; h++) {
    const wire::Bytes& ref = sm[0].applied.at(h - 1);
    BOOST_REQUIRE(!ref.empty());
    for (int i = 1; i < 7; i++) BOOST_TEST((sm[i].applied.at(h - 1) == ref));
  }
}

BOOST_AUTO_TEST_CASE(FourNodesConvergeToSameAppHash) {
  std::vector<KvStateMachine> sm(4);
  sm[0].submit(Op::put(sv("a"), sv("0")));
  sm[1].submit(Op::put(sv("b"), sv("1")));
  sm[2].submit(Op::put(sv("c"), sv("2")));
  sm[3].submit(Op::put(sv("d"), sv("3")));

  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run(5, 4);

  for (int i = 0; i < 4; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() == 5u);
    BOOST_TEST(sm[i].state().size() == 4u);
    for (const char* k : {"a", "b", "c", "d"}) BOOST_REQUIRE(sm[i].state().get(sv(k)) != nullptr);
  }
  Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; i++) BOOST_TEST((c.nodes[i]->composite_hash() == h0));
}

BOOST_AUTO_TEST_CASE(FourNodesVoteInFifthMember) {
  KeyPair cand = KeyPair::generate();
  const PubKey k5 = cand.pub;
  std::array<uint8_t, 32> data{};
  std::copy(k5.begin(), k5.end(), data.begin());

  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);

  for (int i = 0; i < 4; i++)
    c.nodes[i]->submit_gov_vote(consensus::Governance::Kind::Add, k5, data);

  c.run(12, 4);

  for (int i = 0; i < 4; i++) {
    BOOST_TEST(c.nodes[i]->member_count() == 5u);
    BOOST_TEST(c.nodes[i]->is_member(k5));
    BOOST_TEST(c.nodes[i]->validators_for(1).size() == 4u);
    BOOST_TEST(c.nodes[i]->validators_for(c.nodes[i]->last_decided() + 1).size() == 5u);
    BOOST_TEST(c.nodes[i]->decide_misses() == 0u);
  }
  BOOST_TEST(c.nodes[0]->last_decided() >= 8u);
}

BOOST_AUTO_TEST_CASE(FiveNodesVoteOutMember) {
  std::vector<MockStateMachine> sm(5);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);

  PubKey victim{};
  std::copy(c.vset[4].public_key.begin(), c.vset[4].public_key.end(), victim.begin());
  for (int i = 0; i < 4; i++)
    c.nodes[i]->submit_gov_vote(consensus::Governance::Kind::Remove, victim);

  c.run(14, 4);

  for (int i = 0; i < 5; i++) {
    BOOST_TEST(c.nodes[i]->member_count() == 4u);
    BOOST_TEST(!c.nodes[i]->is_member(victim));
    BOOST_TEST(c.nodes[i]->validators_for(1).size() == 5u);
    BOOST_TEST(c.nodes[i]->validators_for(c.nodes[i]->last_decided() + 1).size() == 4u);
  }
  BOOST_TEST(c.nodes[0]->last_decided() >= 10u);
}

BOOST_AUTO_TEST_SUITE_END()
