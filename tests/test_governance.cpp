#include <boost/test/unit_test.hpp>

#include <hyle/core/consensus.h>

#include <array>
#include <vector>

using namespace hyle::consensus;
using Kind = Governance::Kind;

static Governance::Id id(uint8_t b) {
  Governance::Id x{};
  x[0] = b;
  return x;
}
static Validator val(uint8_t b) {
  Validator v;
  v.key[0] = b;
  v.power = 1;
  return v;
}
static std::vector<Governance::Member> gen(std::vector<uint8_t> ids) {
  std::vector<Governance::Member> m;
  for (uint8_t b : ids) m.push_back({id(b), Governance::Id{}});
  return m;
}

BOOST_AUTO_TEST_SUITE(ScheduleTests)

BOOST_AUTO_TEST_CASE(GenesisBeforeAnyChange) {
  ValidatorSetSchedule s({val(1), val(2)}, 1, 2);
  BOOST_TEST(s.setForHeight(1).size() == 2u);
  BOOST_TEST(s.setForHeight(1000).size() == 2u);
}

BOOST_AUTO_TEST_CASE(ChangeTakesEffectAtPlusDelay) {
  ValidatorSetSchedule s({val(1), val(2)}, 1, 2);
  s.onDecided(5, {val(1), val(2), val(3)});
  BOOST_TEST(s.setForHeight(6).size() == 2u);
  BOOST_TEST(s.setForHeight(7).size() == 3u);
  BOOST_TEST(s.setForHeight(100).size() == 3u);
}

BOOST_AUTO_TEST_CASE(DedupOnUnchangedMembership) {
  ValidatorSetSchedule s({val(1), val(2)}, 1, 2);
  s.onDecided(5, {val(1), val(2)});
  BOOST_TEST(s.setForHeight(7).size() == 2u);
  s.onDecided(9, {val(1), val(2), val(3)});
  BOOST_TEST(s.setForHeight(10).size() == 2u);
  BOOST_TEST(s.setForHeight(11).size() == 3u);
}

BOOST_AUTO_TEST_CASE(OutOfOrderDecidedHeightIgnored) {
  ValidatorSetSchedule s({val(1), val(2)}, 1, 2);
  s.onDecided(10, {val(1), val(2), val(3)});
  BOOST_TEST(s.setForHeight(12).size() == 3u);

  s.onDecided(5, {val(1)});
  BOOST_TEST(s.setForHeight(7).size() == 2u);
  BOOST_TEST(s.setForHeight(12).size() == 3u);

  s.onDecided(10, {val(1), val(2), val(3)});
  BOOST_TEST(s.setForHeight(12).size() == 3u);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(GovernanceTests)

BOOST_AUTO_TEST_CASE(AddReachesQuorum) {
  Governance g(gen({1, 2, 3, 4}), /*cap=*/10);
  BOOST_TEST(!g.vote(id(1), Kind::Add, id(5)));
  BOOST_TEST(!g.vote(id(2), Kind::Add, id(5)));
  BOOST_TEST(g.vote(id(3), Kind::Add, id(5)));
  BOOST_TEST(g.isMember(id(5)));
  BOOST_TEST(g.size() == 5u);
}

BOOST_AUTO_TEST_CASE(NonMemberCannotVote) {
  Governance g(gen({1, 2, 3, 4}), 10);
  BOOST_TEST(!g.vote(id(99), Kind::Add, id(5)));
  BOOST_TEST(!g.vote(id(99), Kind::Add, id(5)));
  BOOST_TEST(!g.vote(id(99), Kind::Add, id(5)));
  BOOST_TEST(!g.isMember(id(5)));
}

BOOST_AUTO_TEST_CASE(RemoveReachesQuorum) {
  Governance g(gen({1, 2, 3, 4}), 10, /*floor=*/1);
  g.vote(id(1), Kind::Remove, id(4));
  g.vote(id(2), Kind::Remove, id(4));
  BOOST_TEST(g.vote(id(3), Kind::Remove, id(4)));
  BOOST_TEST(!g.isMember(id(4)));
  BOOST_TEST(g.size() == 3u);
}

BOOST_AUTO_TEST_CASE(FloorBlocksRemoval) {
  Governance g(gen({1, 2}), 10, /*floor=*/2);
  g.vote(id(1), Kind::Remove, id(2));
  BOOST_TEST(!g.vote(id(2), Kind::Remove, id(2)));
  BOOST_TEST(g.size() == 2u);
}

BOOST_AUTO_TEST_CASE(CapBlocksAddition) {
  Governance g(gen({1, 2, 3}), /*cap=*/4);
  g.vote(id(1), Kind::Add, id(4));
  g.vote(id(2), Kind::Add, id(4));
  BOOST_TEST(g.vote(id(3), Kind::Add, id(4)));
  BOOST_TEST(g.size() == 4u);
  g.vote(id(1), Kind::Add, id(5));
  g.vote(id(2), Kind::Add, id(5));
  BOOST_TEST(!g.vote(id(3), Kind::Add, id(5)));
  BOOST_TEST(!g.isMember(id(5)));
  BOOST_TEST(g.size() == 4u);
}

BOOST_AUTO_TEST_CASE(OrderIndependentDeterminism) {
  Governance a(gen({1, 2, 3, 4}), 10);
  a.vote(id(1), Kind::Add, id(5));
  a.vote(id(2), Kind::Add, id(5));
  a.vote(id(3), Kind::Add, id(5));

  Governance b(gen({1, 2, 3, 4}), 10);
  b.vote(id(3), Kind::Add, id(5));
  b.vote(id(1), Kind::Add, id(5));
  b.vote(id(2), Kind::Add, id(5));

  BOOST_TEST((a.members() == b.members()));
}

BOOST_AUTO_TEST_CASE(MemberCanVoteToRemoveItself) {
  Governance g(gen({1, 2, 3, 4}), 10);
  g.vote(id(1), Kind::Remove, id(1));
  g.vote(id(2), Kind::Remove, id(1));
  BOOST_TEST(g.vote(id(3), Kind::Remove, id(1)));
  BOOST_TEST(!g.isMember(id(1)));
  BOOST_TEST(g.size() == 3u);
}

BOOST_AUTO_TEST_CASE(AddThenRemoveReturnsToGenesis) {
  Governance g(gen({1, 2, 3, 4}), 10);
  g.vote(id(1), Kind::Add, id(5));
  g.vote(id(2), Kind::Add, id(5));
  BOOST_TEST(g.vote(id(3), Kind::Add, id(5)));
  BOOST_TEST(g.size() == 5u);
  g.vote(id(1), Kind::Remove, id(5));
  g.vote(id(2), Kind::Remove, id(5));
  g.vote(id(3), Kind::Remove, id(5));
  BOOST_TEST(g.vote(id(4), Kind::Remove, id(5)));
  BOOST_TEST(g.size() == 4u);
  BOOST_TEST(!g.isMember(id(5)));
}

BOOST_AUTO_TEST_CASE(CompetingAddDataNeedsAgreement) {
  Governance g(gen({1, 2, 3, 4}), 10);
  std::array<uint8_t, 32> A{};
  A[0] = 0xAA;
  std::array<uint8_t, 32> B{};
  B[0] = 0xBB;
  g.vote(id(1), Kind::Add, id(5), A);
  g.vote(id(2), Kind::Add, id(5), A);
  g.vote(id(3), Kind::Add, id(5), B);
  g.vote(id(4), Kind::Add, id(5), B);
  BOOST_TEST(!g.isMember(id(5)));
  BOOST_TEST(g.vote(id(3), Kind::Add, id(5), A));
  BOOST_TEST(g.isMember(id(5)));
  for (const auto& m : g.members())
    if (m.first == id(5)) BOOST_TEST((m.second == A));
}

BOOST_AUTO_TEST_CASE(RemoveDownToFloorThenBlocked) {
  Governance g(gen({1, 2, 3, 4, 5}), 10, /*floor=*/1);
  for (uint8_t t : {5, 4, 3, 2}) {
    for (uint8_t v : {1, 2, 3, 4, 5}) {
      if (!g.isMember(id(v))) continue;
      g.vote(id(v), Kind::Remove, id(t));
    }
  }
  BOOST_TEST(g.size() == 1u);
  BOOST_TEST(!g.vote(id(1), Kind::Remove, id(1)));
  BOOST_TEST(g.size() == 1u);
}

BOOST_AUTO_TEST_CASE(CapEqualsGenesisBlocksAdd) {
  Governance g(gen({1, 2, 3}), /*cap=*/3);
  g.vote(id(1), Kind::Add, id(4));
  g.vote(id(2), Kind::Add, id(4));
  BOOST_TEST(!g.vote(id(3), Kind::Add, id(4)));
  BOOST_TEST(!g.isMember(id(4)));
  BOOST_TEST(g.size() == 3u);
}

BOOST_AUTO_TEST_CASE(DuplicateVoteCountsOnce) {
  Governance g(gen({1, 2, 3, 4}), 10);
  g.vote(id(1), Kind::Add, id(5));
  g.vote(id(1), Kind::Add, id(5));
  g.vote(id(1), Kind::Add, id(5));
  BOOST_TEST(!g.isMember(id(5)));
  g.vote(id(2), Kind::Add, id(5));
  BOOST_TEST(g.vote(id(3), Kind::Add, id(5)));
  BOOST_TEST(g.isMember(id(5)));
}

BOOST_AUTO_TEST_CASE(SettleCascadesRemoveThenBlockedAdd) {
  Governance g(gen({1, 2, 3, 4}), /*cap=*/4);
  g.vote(id(1), Kind::Add, id(5));
  g.vote(id(2), Kind::Add, id(5));
  g.vote(id(3), Kind::Add, id(5));
  BOOST_TEST(!g.isMember(id(5)));
  BOOST_TEST(g.size() == 4u);

  g.vote(id(1), Kind::Remove, id(4));
  g.vote(id(2), Kind::Remove, id(4));
  BOOST_TEST(g.vote(id(3), Kind::Remove, id(4)));
  BOOST_TEST(!g.isMember(id(4)));
  BOOST_TEST(g.isMember(id(5)));
  BOOST_TEST(g.size() == 4u);
}

BOOST_AUTO_TEST_SUITE_END()
