#include <boost/test/unit_test.hpp>

#include "local_cluster.h"

#include <hyle/core/crypto.h>
#include <hyle/services/kv/ledger.h>

#include <cstring>
#include <string>
#include <vector>

using namespace hyle;

static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
static std::string content_str(const Ledger& l, const std::string& name) {
  wire::Bytes c = l.name_content(sv(name));
  return std::string(c.begin(), c.end());
}
static PubKey name_key_pk(const std::string& name) {
  Hash h = Ledger::name_key(sv(name));
  PubKey k{};
  std::memcpy(k.data(), h.data(), 32);
  return k;
}

BOOST_AUTO_TEST_SUITE(RegistryTests)

BOOST_AUTO_TEST_CASE(RegisterFirstComeWins) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();

  l.submit_name(Ledger::make_register(A, sv("foo"), sv("hello")));
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  BOOST_TEST(l.has_name(sv("foo")));
  BOOST_TEST((l.name_owner(sv("foo")) == A.pub));
  BOOST_TEST(content_str(l, "foo") == "hello");
  BOOST_TEST(l.name_version(sv("foo")) == 1u);

  l.submit_name(Ledger::make_register(B, sv("foo"), sv("evil")));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));
  BOOST_TEST((l.name_owner(sv("foo")) == A.pub));
  BOOST_TEST(content_str(l, "foo") == "hello");
}

BOOST_AUTO_TEST_CASE(UpdateRequiresOwnerAndFreshVersion) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  l.submit_name(Ledger::make_register(A, sv("foo"), sv("v1")));
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));

  l.submit_name(Ledger::make_update(A, sv("foo"), 2, sv("v2")));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));
  BOOST_TEST(content_str(l, "foo") == "v2");
  BOOST_TEST(l.name_version(sv("foo")) == 2u);

  l.submit_name(Ledger::make_update(B, sv("foo"), 3, sv("evil")));
  l.apply_payload(ApplyContext{3, A.pub}, l.build_payload(3));
  BOOST_TEST(content_str(l, "foo") == "v2");
  BOOST_TEST(l.name_version(sv("foo")) == 2u);
  BOOST_TEST((l.name_owner(sv("foo")) == A.pub));

  l.submit_name(Ledger::make_update(A, sv("foo"), 2, sv("stale")));
  l.apply_payload(ApplyContext{4, A.pub}, l.build_payload(4));
  BOOST_TEST(content_str(l, "foo") == "v2");
  BOOST_TEST(l.name_version(sv("foo")) == 2u);
}

BOOST_AUTO_TEST_CASE(GiveTransfersOwnership) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  l.submit_name(Ledger::make_register(A, sv("foo"), sv("x")));
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));

  l.submit_name(Ledger::make_give(A, sv("foo"), 2, B.pub));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));
  BOOST_TEST((l.name_owner(sv("foo")) == B.pub));

  l.submit_name(Ledger::make_update(A, sv("foo"), 3, sv("a")));
  l.submit_name(Ledger::make_update(B, sv("foo"), 3, sv("b")));
  l.apply_payload(ApplyContext{3, A.pub}, l.build_payload(3));
  BOOST_TEST(content_str(l, "foo") == "b");
  BOOST_TEST((l.name_owner(sv("foo")) == B.pub));
  BOOST_TEST(l.name_version(sv("foo")) == 3u);
  l.submit_name(Ledger::make_update(B, sv("foo"), 4, sv("b2")));
  l.apply_payload(ApplyContext{4, A.pub}, l.build_payload(4));
  BOOST_TEST(content_str(l, "foo") == "b2");
  BOOST_TEST(l.name_version(sv("foo")) == 4u);
}

BOOST_AUTO_TEST_CASE(ReleaseDeletesNameAndBurnsBalance) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  const PubKey nk = name_key_pk("foo");
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  l.submit_name(Ledger::make_register(A, sv("foo"), sv("x")));
  l.submit(Ledger::make_transfer(A, nk, 40));
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(l.has_name(sv("foo")));
  BOOST_TEST(l.balance(nk) == 40u);
  const uint64_t before = l.total();

  l.submit_name(Ledger::make_release(A, sv("foo"), 2));
  l.apply_payload(ApplyContext{3, PubKey{}}, l.build_payload(3));
  BOOST_TEST(!l.has_name(sv("foo")));
  BOOST_TEST(l.balance(nk) == 0u);
  BOOST_TEST(l.total() == before - 40u);
}

BOOST_AUTO_TEST_CASE(NameFundedThenRentEvicts) {
  Ledger l(1);
  KeyPair A = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  const PubKey nk = name_key_pk("foo");

  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));

  l.submit_name(Ledger::make_register(A, sv("foo"), sv("abc")));
  l.submit(Ledger::make_transfer(A, nk, 10));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));
  BOOST_TEST(l.has_name(sv("foo")));
  BOOST_TEST(l.balance(nk) == 10u);

  for (uint64_t h = 3; h <= 5; ++h) l.apply_payload(ApplyContext{h, A.pub}, l.build_payload(h));
  BOOST_TEST(l.has_name(sv("foo")));

  l.submit_evict(nk, C.pub);
  l.apply_payload(ApplyContext{6, A.pub}, l.build_payload(6));
  BOOST_TEST(!l.has_name(sv("foo")));
  BOOST_TEST(l.balance(C.pub) == Ledger::BOUNTY);
}

BOOST_AUTO_TEST_CASE(FreshRegisteredNameNotEvictableForBounty) {
  Ledger l(1);
  KeyPair A = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  const PubKey nk = name_key_pk("n");
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  const uint64_t before = l.total();
  l.submit_name(Ledger::make_register(A, sv("n"), sv("")));
  l.submit_evict(nk, C.pub);
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(l.has_name(sv("n")));
  BOOST_TEST(l.balance(C.pub) == 0u);
  BOOST_TEST(l.total() == before);
}

BOOST_AUTO_TEST_CASE(UnknownNameKindRejectedAtDecode) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  wire::Bytes raw;
  wire::Writer w(raw);
  w.count(0);
  w.count(0);
  w.count(1);
  w.u8(9);
  w.raw(wire::View(A.pub.data(), A.pub.size()));
  w.bytes(sv("foo"));
  w.u64(1);
  w.bytes(sv(""));
  Sig s{};
  w.raw(wire::View(s.data(), s.size()));
  w.count(0);
  BOOST_TEST(!l.validate_payload(wire::View(raw.data(), raw.size())));
}

BOOST_AUTO_TEST_CASE(MultiNodeRegistryConverges) {
  std::vector<Ledger> led(4);
  KeyPair A = KeyPair::generate();
  led[0].submit_name(Ledger::make_register(A, sv("alice"), sv("home")));
  std::vector<StateMachine*> sms;
  for (auto& x : led) sms.push_back(&x);
  LocalCluster c(sms);
  c.run(8, 4);

  for (int i = 0; i < 4; i++) {
    BOOST_TEST(led[i].has_name(sv("alice")));
    BOOST_TEST((led[i].name_owner(sv("alice")) == A.pub));
  }
  Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; i++) BOOST_TEST((c.nodes[i]->composite_hash() == h0));
}

BOOST_AUTO_TEST_SUITE_END()
