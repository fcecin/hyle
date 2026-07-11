#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <hyle/services/kv/kv_state_machine.h>
#include <hyle/services/kv/ops.h>
#include <hyle/services/kv/state.h>

#include <stdexcept>
#include <string>
#include <vector>

using namespace hyle;
using namespace hyle::services::kv;

static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

BOOST_AUTO_TEST_SUITE(NodeTests)

BOOST_AUTO_TEST_CASE(SingleNodeDecidesEachHeightMock) {
  MockStateMachine sm;
  std::vector<StateMachine*> sms{&sm};
  LocalCluster c(sms);
  c.run(3, 1);
  BOOST_TEST(c.nodes[0]->last_decided() == 3u);
  BOOST_TEST(sm.applied.size() == 3u);
  for (uint64_t h = 1; h <= 3; ++h) {
    wire::Reader r(sm.applied[h - 1]);
    BOOST_TEST(r.u64() == h);
  }
}

BOOST_AUTO_TEST_CASE(SingleNodeKvAppliesOpsAndAppHashMatches) {
  KvStateMachine sm;
  sm.submit(Op::put(sv("alpha"), sv("1")));
  sm.submit(Op::put(sv("beta"), sv("2")));
  sm.submit(Op::del(sv("alpha")));

  std::vector<StateMachine*> sms{&sm};
  LocalCluster c(sms);
  c.run(1, 1);

  BOOST_TEST(c.nodes[0]->last_decided() == 1u);
  BOOST_TEST(sm.state().size() == 1u);
  const wire::Bytes* beta = sm.state().get(sv("beta"));
  BOOST_REQUIRE(beta != nullptr);
  BOOST_TEST(std::string(beta->begin(), beta->end()) == "2");
  BOOST_TEST(sm.state().get(sv("alpha")) == static_cast<const wire::Bytes*>(nullptr));

  State ref;
  ref.apply(Op::put(sv("alpha"), sv("1")));
  ref.apply(Op::put(sv("beta"), sv("2")));
  ref.apply(Op::del(sv("alpha")));
  BOOST_TEST(sm.state().app_hash() == ref.app_hash());
}

BOOST_AUTO_TEST_CASE(WeightedGenesisRejected) {
  PrivKey secret{};
  secret[0] = 1;
  KeyPair kp = KeyPair::from_secret(secret);
  malachite::Validator v;
  v.address = malachite::Bytes(kp.pub.begin(), kp.pub.end());
  v.public_key = v.address;

  v.voting_power = 5;
  malachite::ValidatorSet weighted{v};
  MockStateMachine sm1;
  BOOST_CHECK_THROW(Node(kp, weighted, sm1, NodeConfig{}), std::invalid_argument);

  v.voting_power = 1;
  malachite::ValidatorSet plain{v};
  MockStateMachine sm2;
  BOOST_CHECK_NO_THROW(Node(kp, plain, sm2, NodeConfig{}));
}

BOOST_AUTO_TEST_CASE(WrongSizeGenesisKeyRejected) {
  PrivKey secret{};
  secret[0] = 2;
  KeyPair kp = KeyPair::from_secret(secret);
  malachite::Validator v;
  v.address = malachite::Bytes(kp.pub.begin(), kp.pub.end());
  v.public_key = malachite::Bytes(31, 0x11);
  v.voting_power = 1;
  malachite::ValidatorSet bad{v};
  MockStateMachine sm;
  BOOST_CHECK_THROW(Node(kp, bad, sm, NodeConfig{}), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()
