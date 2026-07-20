#include <boost/test/unit_test.hpp>

#include "mock_state_machine.h"

#include <hyle/core/crypto.h>
#include <hyle/core/node.h>
#include <hyle/core/wire.h>

#include <vector>

using namespace hyle;

namespace {

malachite::ValidatorSet make_vset(const std::vector<KeyPair>& ks) {
  malachite::ValidatorSet vs;
  for (const auto& k : ks) {
    malachite::Validator v;
    v.address = malachite::Bytes(k.pub.begin(), k.pub.end());
    v.public_key = v.address;
    v.voting_power = 1;
    vs.push_back(v);
  }
  return vs;
}

// Value envelope: [parent 32][u32 n_gov][gov ops][payload].
wire::Bytes make_value(const Hash& parent, const std::vector<GovOp>& gov, wire::View payload) {
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(parent.data(), parent.size()));
  w.count(gov.size());
  for (const auto& g : gov) {
    w.u8(static_cast<uint8_t>(g.kind));
    w.raw(wire::View(g.voter.data(), g.voter.size()));
    w.raw(wire::View(g.target.data(), g.target.size()));
    w.raw(wire::View(g.data.data(), g.data.size()));
    w.raw(wire::View(g.sig.data(), g.sig.size()));
  }
  w.raw(payload);
  return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(BaseTests)

BOOST_AUTO_TEST_CASE(AcceptsWellFormedValue) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  wire::Bytes v = make_value(node.composite_hash(), {}, {});
  BOOST_TEST(node.accept_proposed(malachite::BytesView(v)));
}

BOOST_AUTO_TEST_CASE(RejectsStaleParent) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  Hash wrong{};
  wire::Bytes v = make_value(wrong, {}, {});
  BOOST_TEST(!node.accept_proposed(malachite::BytesView(v)));
}

// The fix for the decide-time abort: a stale-parent proposal is Behind (sync, do not vote), NOT
// Invalid. Feeding Invalid for a value the network decides aborts malachite at the decide step. Only
// deterministic defects (malformed, and the others) are Invalid.
BOOST_AUTO_TEST_CASE(CheckProposedSeparatesBehindFromInvalid) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  wire::Bytes ok = make_value(node.composite_hash(), {}, {});
  BOOST_TEST((node.check_proposed(malachite::BytesView(ok)) == ProposalCheck::Valid));
  Hash wrong{};
  wrong[0] = 0xAB;  // well-formed, but built on committed state we do not have: behind, not invalid
  wire::Bytes stale = make_value(wrong, {}, {});
  BOOST_TEST((node.check_proposed(malachite::BytesView(stale)) == ProposalCheck::Behind));
  wire::Bytes truncated{0x00, 0x01, 0x02};  // malformed: a deterministic Invalid
  BOOST_TEST((node.check_proposed(malachite::BytesView(truncated)) == ProposalCheck::Invalid));
}

BOOST_AUTO_TEST_CASE(RejectsAppInvalidPayload) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  sm.accept = false;
  Node node(ks[0], make_vset(ks), sm);
  wire::Bytes v = make_value(node.composite_hash(), {}, {});
  BOOST_TEST(!node.accept_proposed(malachite::BytesView(v)));
}

BOOST_AUTO_TEST_CASE(RejectsBadGovSignature) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  GovOp g;
  g.kind = consensus::Governance::Kind::Add;
  g.voter = ks[1].pub;
  g.target = KeyPair::generate().pub;
  g.sig = Sig{};
  wire::Bytes v = make_value(node.composite_hash(), {g}, {});
  BOOST_TEST(!node.accept_proposed(malachite::BytesView(v)));
}

BOOST_AUTO_TEST_CASE(RejectsNonMemberVoter) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  KeyPair outsider = KeyPair::generate();
  GovOp g;
  g.kind = consensus::Governance::Kind::Add;
  g.voter = outsider.pub;
  g.target = KeyPair::generate().pub;
  g.sig = Sig{};
  wire::Bytes v = make_value(node.composite_hash(), {g}, {});
  BOOST_TEST(!node.accept_proposed(malachite::BytesView(v)));
}

BOOST_AUTO_TEST_CASE(RejectsMalformedEnvelope) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  wire::Bytes truncated{0x00, 0x01, 0x02};
  BOOST_TEST(!node.accept_proposed(malachite::BytesView(truncated)));
}

BOOST_AUTO_TEST_CASE(RejectsOversizedValue) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  NodeConfig cfg;
  cfg.max_value_bytes = 64;
  Node node(ks[0], make_vset(ks), sm, cfg);
  wire::Bytes payload(200, 0x11);
  wire::Bytes big = make_value(node.composite_hash(), {}, wire::View(payload));
  BOOST_TEST(big.size() > 64u);
  BOOST_TEST(!node.accept_proposed(malachite::BytesView(big)));
}

BOOST_AUTO_TEST_CASE(ChainIdScopesAppHash) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sa, sb;
  NodeConfig ca;
  ca.chain_id = "chain-A";
  NodeConfig cb;
  cb.chain_id = "chain-B";
  Node na(ks[0], make_vset(ks), sa, ca);
  Node nb(ks[0], make_vset(ks), sb, cb);
  BOOST_TEST(!(na.composite_hash() == nb.composite_hash()));
}

BOOST_AUTO_TEST_CASE(ValueCacheIsBounded) {
  std::vector<KeyPair> ks{KeyPair::generate(), KeyPair::generate(), KeyPair::generate(),
                          KeyPair::generate()};
  MockStateMachine sm;
  Node node(ks[0], make_vset(ks), sm);
  Hash parent = node.composite_hash();
  for (uint32_t i = 0; i < 5000; ++i) {
    wire::Bytes payload;
    wire::Writer(payload).u32(i);
    wire::Bytes v = make_value(parent, {}, wire::View(payload));
    node.accept_proposed(malachite::BytesView(v));
  }
  BOOST_TEST(node.value_cache_size() <= 4096u);
}

BOOST_AUTO_TEST_SUITE_END()
