#include <boost/test/unit_test.hpp>

#include "local_cluster.h"

#include <hyle/core/crypto.h>
#include <hyle/services/app.h>
#include <hyle/services/ops.h>
#include <hyle/services/runtime.h>
#include <hyle/services/schema.h>

#include <string>
#include <vector>

using namespace hyle;

namespace {

wire::View wv(const wire::Bytes& b) { return wire::View(b.data(), b.size()); }

wire::Bytes acct_key(const PubKey& pk) {
  wire::Bytes b;
  b.push_back(services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}
wire::Bytes ent_key(const std::string& name) {
  wire::Bytes b;
  b.push_back(services::ENTRY_PREFIX);
  b.insert(b.end(), name.begin(), name.end());
  return b;
}

// A sudo act's inner bytes are an op batch with signatures and sequences left empty: the
// votes on the proposal are the authorization, so the op does not carry its own.
wire::Bytes inner_transfer(const PubKey& from, const wire::Bytes& to, uint64_t amount) {
  services::Decoded d;
  services::TransferOp t;
  t.from = from;
  t.to = to;
  t.amount = amount;
  d.transfers.push_back(t);
  return services::encode_ops(d);
}
wire::Bytes inner_entry(services::EntryKind kind, const PubKey& signer, const std::string& name,
                        uint64_t amount = 0, const PubKey& aux = PubKey{},
                        const std::string& payload = {}) {
  services::Decoded d;
  services::EntryOp e;
  e.kind = kind;
  e.signer = signer;
  e.name.assign(name.begin(), name.end());
  e.amount = amount;
  e.aux = aux;
  e.payload.assign(payload.begin(), payload.end());
  d.entries.push_back(e);
  return services::encode_ops(d);
}

std::string payload_str(const services::App& app, const std::string& name) {
  wire::Bytes n(name.begin(), name.end());
  wire::Bytes p = app.entry_payload(wv(n));
  return std::string(p.begin(), p.end());
}
bool has_entry(const services::App& app, const std::string& name) {
  wire::Bytes n(name.begin(), name.end());
  return app.entry_exists(wv(n));
}
PubKey entry_owner(const services::App& app, const std::string& name) {
  wire::Bytes n(name.begin(), name.end());
  return app.entry_owner(wv(n));
}
uint64_t entry_balance(const services::App& app, const std::string& name) {
  wire::Bytes n(name.begin(), name.end());
  return app.entry_balance(wv(n));
}

// A one-validator chain: its own quorum, so a Propose executes in the block that opens it.
struct Solo {
  KeyPair v = KeyPair::generate();
  services::Genesis g;
  std::unique_ptr<services::Runtime> rt;

  explicit Solo(uint64_t alloc = 100000, uint64_t rent_rate = 0, uint64_t ttl = 0) {
    g.chain_id = "sudotest";
    g.validators = {v.pub};
    g.allocations = {{v.pub, alloc}};
    g.config.rent_rate = rent_rate;
    g.config.fee_sudo = 0;  // keep the arithmetic in these tests about the acts, not the op fee
    g.config.sudo_ttl_secs = ttl;
    rt = std::make_unique<services::Runtime>(g, v, 0);
    rt->run_to(1);
  }

  services::App& app() { return rt->app(); }
  wire::View chain() const {
    return wire::View(reinterpret_cast<const uint8_t*>(g.chain_id.data()), g.chain_id.size());
  }
  uint64_t seq() { return app().sequence(v.pub); }

  // Would this act be admitted as a proposal (shape + sig valid)?
  bool admits(const wire::Bytes& inner) {
    return rt->submit(services::make_sudo_propose(v, seq(), wv(inner), chain())) == services::Admit::Ok;
  }
  // Propose an act as the sole validator and run until it commits (and thus executes).
  bool propose(const wire::Bytes& inner) {
    if (!admits(inner)) return false;
    rt->run_to(rt->height() + 2);
    return true;
  }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(SudoTests)

BOOST_AUTO_TEST_CASE(SoloValidatorIsItsOwnQuorum) {
  Solo s;
  BOOST_TEST(s.rt->app().config().fee_sudo == 0u);
  // no proposal yet
  services::Pending p;
  BOOST_TEST(!s.app().pending_info(s.v.pub, p));
}

// Sudo mints from the sentinel; a solo Propose reaches quorum and executes in one block.
BOOST_AUTO_TEST_CASE(SudoMintsFromTheSentinel) {
  Solo s;
  KeyPair x = KeyPair::generate();
  const uint64_t before = s.app().balance(s.v.pub);

  BOOST_TEST(s.propose(inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 500)));

  BOOST_TEST(s.app().balance(x.pub) == 500u);
  BOOST_TEST(s.app().sudo_minted() == 500u);
  BOOST_TEST(s.app().balance(s.v.pub) == before);  // nothing debited to fund it
  services::Pending p;
  BOOST_TEST(!s.app().pending_info(s.v.pub, p));  // the cell is gone once executed
}

BOOST_AUTO_TEST_CASE(SudoMintNeedsNoAccountAndChargesNoFee) {
  Solo s;
  KeyPair x = KeyPair::generate();
  BOOST_TEST(!s.app().account_exists(x.pub));
  BOOST_TEST(s.propose(inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 7)));
  BOOST_TEST(s.app().balance(x.pub) == 7u);
  BOOST_TEST(s.app().sequence(x.pub) == 0u);
}

BOOST_AUTO_TEST_CASE(SudoSeizesWithoutASignatureOrSequence) {
  Solo s;
  KeyPair x = KeyPair::generate();
  const uint64_t before = s.app().balance(s.v.pub);

  BOOST_TEST(s.propose(inner_transfer(s.v.pub, acct_key(x.pub), 400)));

  BOOST_TEST(s.app().balance(s.v.pub) == before - 400u);  // exactly, no transfer fee
  BOOST_TEST(s.app().balance(x.pub) == 400u);
  BOOST_TEST(s.app().sudo_minted() == 0u);  // a seizure creates nothing
}

BOOST_AUTO_TEST_CASE(SudoSeizureCannotMintWhenTheSourceIsShort) {
  Solo s(/*alloc=*/100);
  KeyPair x = KeyPair::generate();
  BOOST_TEST(s.propose(inner_transfer(s.v.pub, acct_key(x.pub), 1000)));  // authorized, unfunded
  BOOST_TEST(s.app().balance(s.v.pub) == 100u);
  BOOST_TEST(s.app().balance(x.pub) == 0u);
  BOOST_TEST(s.app().sudo_minted() == 0u);
}

BOOST_AUTO_TEST_CASE(SudoPutOverridesTheOwnerGate) {
  Solo s;
  KeyPair owner = KeyPair::generate();
  KeyPair usurper = KeyPair::generate();

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Put, owner.pub, "k", 0, PubKey{}, "v1")));
  BOOST_TEST((entry_owner(s.app(), "k") == owner.pub));
  BOOST_TEST(payload_str(s.app(), "k") == "v1");

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Put, usurper.pub, "k", 0, PubKey{}, "v2")));
  BOOST_TEST((entry_owner(s.app(), "k") == usurper.pub));
  BOOST_TEST(payload_str(s.app(), "k") == "v2");
}

BOOST_AUTO_TEST_CASE(SudoGivesAndDeletesAndRips) {
  Solo s;
  KeyPair a = KeyPair::generate();
  KeyPair b = KeyPair::generate();

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Put, a.pub, "g", 250, PubKey{}, "x")));
  BOOST_TEST(entry_balance(s.app(), "g") == 250u);
  BOOST_TEST(s.app().sudo_minted() == 250u);

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Give, a.pub, "g", 0, b.pub)));
  BOOST_TEST((entry_owner(s.app(), "g") == b.pub));

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Del, a.pub, "g")));
  BOOST_TEST(!has_entry(s.app(), "g"));
  BOOST_TEST(s.app().balance(b.pub) == 250u);  // refunded to the current owner

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Put, a.pub, "r", 90, PubKey{}, "y")));
  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Rip, a.pub, "r")));
  BOOST_TEST(!has_entry(s.app(), "r"));
  BOOST_TEST(s.app().balance(a.pub) == 0u);  // Rip refunds no one
}

BOOST_AUTO_TEST_CASE(SudoRefusesToStrandAnEntryOnTheSentinel) {
  Solo s;
  // these never pass validation, so the proposal is not even admitted
  BOOST_TEST(!s.admits(inner_entry(services::EntryKind::Put, services::MINT_SENTINEL, "o")));
  KeyPair a = KeyPair::generate();
  BOOST_TEST(!s.admits(inner_entry(services::EntryKind::Give, a.pub, "o", 0, services::MINT_SENTINEL)));

  // a mint cannot create an entry, only fund one that exists
  BOOST_TEST(s.propose(inner_transfer(services::MINT_SENTINEL, ent_key("ghost"), 10)));
  BOOST_TEST(!has_entry(s.app(), "ghost"));
  BOOST_TEST(s.app().sudo_minted() == 0u);

  BOOST_TEST(s.propose(inner_entry(services::EntryKind::Put, a.pub, "real", 0, PubKey{}, "p")));
  BOOST_TEST(s.propose(inner_transfer(services::MINT_SENTINEL, ent_key("real"), 10)));
  BOOST_TEST(entry_balance(s.app(), "real") == 10u);
}

BOOST_AUTO_TEST_CASE(ProofOfWorkAndEmptyRejectedAsInner) {
  Solo s;
  services::Decoded m;
  m.mints.push_back(services::MintOp{});
  BOOST_TEST(!s.admits(services::encode_ops(m)));
  services::Decoded empty;  // well-formed, authorizes nothing
  BOOST_TEST(!s.admits(services::encode_ops(empty)));
}

// The op is paid for like any other. A member with no funds cannot even propose.
BOOST_AUTO_TEST_CASE(ProposeChargesTheOpFee) {
  KeyPair v = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "feetest";
  g.validators = {v.pub};
  g.allocations = {{v.pub, 100}};
  g.config.fee_sudo = 40;
  services::Runtime rt(g, v, 0);
  rt.run_to(1);
  const wire::View chain(reinterpret_cast<const uint8_t*>(g.chain_id.data()), g.chain_id.size());

  KeyPair x = KeyPair::generate();
  BOOST_TEST((rt.submit(services::make_sudo_propose(
                  v, 0, wv(inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 5)), chain)) ==
              services::Admit::Ok));
  rt.run_to(rt.height() + 2);
  BOOST_TEST(rt.app().balance(v.pub) == 60u);   // 100 - fee_sudo
  BOOST_TEST(rt.app().balance(x.pub) == 5u);
}

BOOST_AUTO_TEST_CASE(SudoMintedSurvivesAnAppSnapshot) {
  Solo s;
  KeyPair x = KeyPair::generate();
  BOOST_TEST(s.propose(inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 900)));
  BOOST_TEST(s.app().sudo_minted() == 900u);

  const wire::Bytes snap = s.app().snapshot();
  services::App b;
  b.restore(wv(snap));
  BOOST_TEST(b.sudo_minted() == 900u);
  BOOST_TEST(b.balance(x.pub) == 900u);
}

// A multi-member set. Quorum is three of four, so a proposal sits in its 'g' cell collecting
// votes across blocks until the third lands, then executes. The Solo cases above exercise the
// consensus path in a real Runtime; this drives the collector against a set of more than one.
namespace {
std::vector<KeyPair> gen(int n) {
  std::vector<KeyPair> ks;
  for (int i = 0; i < n; i++) ks.push_back(KeyPair::generate());
  return ks;
}
struct Quorum {
  std::vector<KeyPair> ks;
  std::vector<PubKey> members;
  services::App app;
  std::string chain_id = "quorum4";
  uint64_t h = 0;

  Quorum() : ks(gen(4)) {
    services::Genesis g;
    g.chain_id = chain_id;
    for (auto& k : ks) { g.validators.push_back(k.pub); members.push_back(k.pub); }
    g.config.fee_sudo = 0;
    app = services::App::from_genesis(g);
  }
  wire::View chain() const {
    return wire::View(reinterpret_cast<const uint8_t*>(chain_id.data()), chain_id.size());
  }
  void apply(const services::SudoOp& op) { apply_with(members, 3, op); }
  // Apply a block whose active set / quorum the caller controls, to exercise the set
  // shifting under a proposal that is still collecting votes.
  void apply_with(const std::vector<PubKey>& mem, unsigned quo, const services::SudoOp& op) {
    app.submit_sudo(op);
    ApplyContext ctx;
    ctx.height = ++h;
    ctx.members = mem;
    ctx.quorum = quo;
    app.apply_payload(ctx, app.build_payload(h));
  }
  unsigned approvals(const PubKey& proposer) { return approvals_against(proposer, members); }
  unsigned approvals_against(const PubKey& proposer, const std::vector<PubKey>& mem) {
    services::Pending p;
    if (!app.pending_info(proposer, p)) return 0;
    return app.pending_approvals(p, mem);
  }
  bool pending(const PubKey& proposer) {
    services::Pending p;
    return app.pending_info(proposer, p);
  }
};
}  // namespace

BOOST_AUTO_TEST_CASE(VotesAccumulateOnChainUntilQuorum) {
  Quorum q;
  KeyPair x = KeyPair::generate();
  const wire::Bytes inner = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 777);
  const Hash ih = sha256(wv(inner));

  q.apply(services::make_sudo_propose(q.ks[0], 0, wv(inner), q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 1u);   // just the proposer
  BOOST_TEST(q.app.balance(x.pub) == 0u);       // not yet

  q.apply(services::make_sudo_approve(q.ks[1], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 2u);
  BOOST_TEST(q.app.balance(x.pub) == 0u);

  q.apply(services::make_sudo_approve(q.ks[2], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(!q.pending(q.ks[0].pub));          // quorum reached: executed and erased
  BOOST_TEST(q.app.balance(x.pub) == 777u);
  BOOST_TEST(q.app.sudo_minted() == 777u);
}

BOOST_AUTO_TEST_CASE(ANonMemberProposalOrVoteDoesNothing) {
  Quorum q;
  KeyPair outsider = KeyPair::generate();
  KeyPair x = KeyPair::generate();
  const wire::Bytes inner = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 5);
  const Hash ih = sha256(wv(inner));

  // a non-member cannot open a proposal
  q.apply(services::make_sudo_propose(outsider, 0, wv(inner), q.chain()));
  BOOST_TEST(!q.pending(outsider.pub));

  // and a non-member's approval does not count toward quorum
  q.apply(services::make_sudo_propose(q.ks[0], 0, wv(inner), q.chain()));
  q.apply(services::make_sudo_approve(outsider, 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 1u);
  BOOST_TEST(q.app.balance(x.pub) == 0u);
}

BOOST_AUTO_TEST_CASE(AVoteMustCommitToTheProposedAct) {
  Quorum q;
  KeyPair x = KeyPair::generate();
  const wire::Bytes real = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 100);
  q.apply(services::make_sudo_propose(q.ks[0], 0, wv(real), q.chain()));

  // approving a different hash than what was proposed does not count; a rejected op does not
  // consume the voter's sequence, so the real vote below is still seq 0
  const Hash wrong = sha256(wv(inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 999)));
  q.apply(services::make_sudo_approve(q.ks[1], 0, q.ks[0].pub, wrong, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 1u);

  const Hash ih = sha256(wv(real));
  q.apply(services::make_sudo_approve(q.ks[1], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 2u);  // ks0 + ks1

  // the same voter cannot vote twice to fake a quorum
  q.apply(services::make_sudo_approve(q.ks[1], 1, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 2u);
  BOOST_TEST(q.app.balance(x.pub) == 0u);  // quorum 3 never reached
}

// A proposal older than sudo_ttl cannot be completed, and is cleared on the touch that finds
// it expired. No payment, just a timeout. Driven at the app level with a controllable clock
// and a two-member set (so a single vote does not reach quorum).
BOOST_AUTO_TEST_CASE(AProposalExpiresAfterTheTtl) {
  std::vector<KeyPair> ks = gen(2);
  std::vector<PubKey> members = {ks[0].pub, ks[1].pub};
  services::Genesis g;
  g.chain_id = "ttl";
  for (auto& k : ks) g.validators.push_back(k.pub);
  g.config.fee_sudo = 0;
  g.config.sudo_ttl_secs = 100;
  services::App app = services::App::from_genesis(g);
  const wire::View chain(reinterpret_cast<const uint8_t*>(g.chain_id.data()), g.chain_id.size());

  uint64_t clock = 1000;
  app.set_now_fn([&clock] { return clock; });
  uint64_t h = 0;
  auto apply = [&](const services::SudoOp& op) {
    app.submit_sudo(op);
    ApplyContext ctx;
    ctx.height = ++h;
    ctx.members = members;
    ctx.quorum = 2;
    app.apply_payload(ctx, app.build_payload(h));
  };

  KeyPair x = KeyPair::generate();
  const wire::Bytes inner = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 50);
  const Hash ih = sha256(wv(inner));

  apply(services::make_sudo_propose(ks[0], 0, wv(inner), chain));
  services::Pending p;
  BOOST_TEST(app.pending_info(ks[0].pub, p));  // 1 of 2, pending

  clock += 200;  // past the ttl
  apply(services::make_sudo_approve(ks[1], 0, ks[0].pub, ih, chain));
  BOOST_TEST(!app.pending_info(ks[0].pub, p));  // expired, cleared, and never executed
  BOOST_TEST(app.balance(x.pub) == 0u);
}

// A vote counts only while its caster is a member. If the set shifts under a proposal, a
// departed voter stops counting: the quorum is recomputed against the current set every time,
// which is why apply weighs against validators_for(h), not a stored tally.
BOOST_AUTO_TEST_CASE(VotesAreRecountedAgainstTheCurrentSet) {
  Quorum q;
  KeyPair repl = KeyPair::generate();
  KeyPair x = KeyPair::generate();
  const wire::Bytes inner = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 500);
  const Hash ih = sha256(wv(inner));
  const std::vector<PubKey> full = {q.ks[0].pub, q.ks[1].pub, q.ks[2].pub, q.ks[3].pub};
  const std::vector<PubKey> shifted = {q.ks[0].pub, q.ks[2].pub, q.ks[3].pub, repl.pub};  // ks1 out

  q.apply_with(full, 3, services::make_sudo_propose(q.ks[0], 0, wv(inner), q.chain()));
  q.apply_with(full, 3, services::make_sudo_approve(q.ks[1], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals_against(q.ks[0].pub, full) == 2u);

  // ks1 has left. Its earlier vote no longer counts, so ks2's approval is still only 2 of 3.
  q.apply_with(shifted, 3, services::make_sudo_approve(q.ks[2], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals_against(q.ks[0].pub, shifted) == 2u);  // ks0 + ks2, not the departed ks1
  BOOST_TEST(q.app.balance(x.pub) == 0u);

  q.apply_with(shifted, 3, services::make_sudo_approve(q.ks[3], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(!q.pending(q.ks[0].pub));
  BOOST_TEST(q.app.balance(x.pub) == 500u);
}

// A proposer that leaves the set can never overwrite its slot again, so the base hands the
// app the drop-list and the cell is reclaimed -- the bound is one cell per current validator.
BOOST_AUTO_TEST_CASE(ADepartedProposersCellIsCleared) {
  Quorum q;
  KeyPair x = KeyPair::generate();
  q.apply(services::make_sudo_propose(q.ks[0], 0,
                                    wv(inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 5)),
                                    q.chain()));
  BOOST_TEST(q.pending(q.ks[0].pub));  // 1 of 3, sitting

  q.app.on_validators_removed({q.ks[0].pub});
  BOOST_TEST(!q.pending(q.ks[0].pub));  // proposer gone: cell reclaimed
}

// A resend of the identical act must not throw away approvals already collected.
BOOST_AUTO_TEST_CASE(IdenticalReproposeKeepsVotes) {
  Quorum q;
  KeyPair x = KeyPair::generate();
  const wire::Bytes inner = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 42);
  const Hash ih = sha256(wv(inner));

  q.apply(services::make_sudo_propose(q.ks[0], 0, wv(inner), q.chain()));
  q.apply(services::make_sudo_approve(q.ks[1], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 2u);

  q.apply(services::make_sudo_propose(q.ks[0], 1, wv(inner), q.chain()));  // identical resend, seq 1
  BOOST_TEST(q.approvals(q.ks[0].pub) == 2u);                            // approvals survive

  q.apply(services::make_sudo_approve(q.ks[2], 0, q.ks[0].pub, ih, q.chain()));
  BOOST_TEST(!q.pending(q.ks[0].pub));
  BOOST_TEST(q.app.balance(x.pub) == 42u);
}

// A different act, though, does replace the slot -- that is the intended one-per-member.
BOOST_AUTO_TEST_CASE(ReproposingADifferentActResets) {
  Quorum q;
  KeyPair x = KeyPair::generate();
  const wire::Bytes innerX = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 10);
  const Hash ihX = sha256(wv(innerX));
  q.apply(services::make_sudo_propose(q.ks[0], 0, wv(innerX), q.chain()));
  q.apply(services::make_sudo_approve(q.ks[1], 0, q.ks[0].pub, ihX, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 2u);

  const wire::Bytes innerY = inner_transfer(services::MINT_SENTINEL, acct_key(x.pub), 20);
  q.apply(services::make_sudo_propose(q.ks[0], 1, wv(innerY), q.chain()));  // different act
  BOOST_TEST(q.approvals(q.ks[0].pub) == 1u);  // back to just the proposer
  // an approval of the old act's hash no longer matches the slot
  q.apply(services::make_sudo_approve(q.ks[1], 1, q.ks[0].pub, ihX, q.chain()));
  BOOST_TEST(q.approvals(q.ks[0].pub) == 1u);
}

BOOST_AUTO_TEST_SUITE_END()
