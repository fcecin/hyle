#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mesh_cluster.h"
#include "sim_mesh.h"

#include <hyle/core/crypto.h>
#include <hyle/services/kv/pow.h>
#include <hyle/services/app.h>
#include <hyle/morphe/asio_mesh.h>
#include <hyle/morphe/frame.h>
#include <hyle/morphe/client_rest.h>
#include <hyle/services/keys.h>
#include <hyle/services/keyring.h>
#include <hyle/services/mempool.h>
#include <hyle/morphe/rpc.h>
#include <hyle/morphe/rpc_server.h>
#include <hyle/services/runtime.h>
#include <hyle/services/schema.h>
#include <hyle/morphe/testnet.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/json.hpp>

#include <atomic>
#include <thread>

#include <filesystem>
#include <fstream>
#include <sstream>

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

using namespace hyle;
using namespace hyle::services;
using namespace hyle::services::kv;

static void apply_block(services::App& app, uint64_t height) {
  wire::Bytes p = app.build_payload(height);
  app.apply_payload(ApplyContext{height, PubKey{}}, wire::View(p.data(), p.size()));
}
static wire::View kv_view(const wire::Bytes& b) { return wire::View(b.data(), b.size()); }
static wire::View sv(const char* s) { return wire::View(reinterpret_cast<const uint8_t*>(s), std::strlen(s)); }
static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

namespace json = boost::json;
static std::string to_hex(const uint8_t* p, size_t n) {
  static const char* H = "0123456789abcdef";
  std::string s;
  for (size_t i = 0; i < n; ++i) { s.push_back(H[p[i] >> 4]); s.push_back(H[p[i] & 0x0f]); }
  return s;
}
static std::string tx_hex(const services::TransferOp& op) {
  services::Decoded d;
  d.transfers.push_back(op);
  wire::Bytes b = services::encode_ops(d);
  return to_hex(b.data(), b.size());
}
static wire::Bytes rpc_acct_key(const PubKey& pk) {
  wire::Bytes b;
  b.push_back(services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}
static uint64_t ju64(const json::value& v) {
  if (v.is_uint64()) return v.as_uint64();
  if (v.is_int64()) return static_cast<uint64_t>(v.as_int64());
  return static_cast<uint64_t>(v.as_double());
}

BOOST_AUTO_TEST_SUITE(MorpheSmoke)

BOOST_AUTO_TEST_CASE(SingleNodeDecidesWithMorpheApp) {
  services::App app;
  std::vector<StateMachine*> sms{&app};
  LocalCluster c(sms);
  c.run(3, 1);
  BOOST_TEST(c.nodes[0]->last_decided() == 3u);
  BOOST_TEST(c.nodes[0]->applied_height() == 3u);
}

BOOST_AUTO_TEST_CASE(FourNodesAgreeOnMorpheAppHash) {
  std::vector<services::App> apps(4);
  std::vector<StateMachine*> sms;
  for (auto& a : apps) sms.push_back(&a);
  LocalCluster c(sms);
  c.run(4, 4);
  const Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; i++) BOOST_TEST((c.nodes[i]->composite_hash() == h0));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheEconomy)

BOOST_AUTO_TEST_CASE(MintFundsAccountByRewardMinusFee) {
  services::Config cfg;
  services::App app(cfg);
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  services::MintOp m = services::make_mint(v, app.mint_key(), bene, /*min_diff=*/4);
  const unsigned d = pow_difficulty(m.solution);
  const uint64_t expected = app.mint_reward(d) - cfg.fee_mint;

  app.submit_mint(m);
  apply_block(app, 1);

  BOOST_TEST(app.account_exists(bene.pub));
  BOOST_TEST(app.balance(bene.pub) == expected);
  BOOST_TEST(app.sequence(bene.pub) == 0u);
  BOOST_TEST(app.mint_seen_count() == 1u);
}

BOOST_AUTO_TEST_CASE(CommittedMintReAdmitsAsDuplicate) {
  services::App app;
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  services::MintOp m = services::make_mint(v, app.mint_key(), bene, 4);
  BOOST_TEST((app.admit_mint(m) == services::Admit::Ok));
  app.submit_mint(m);
  apply_block(app, 1);
  BOOST_TEST((app.admit_mint(m) == services::Admit::Duplicate));
}

BOOST_AUTO_TEST_CASE(RipOfMissingEntryRejectedAtAdmission) {
  services::App app;
  wire::Bytes name = {'g', 'h', 'o', 's', 't'};
  services::EntryOp rip = services::make_entry_rip(kv_view(name), KeyPair::generate().pub);
  BOOST_TEST((app.admit_entry(rip) != services::Admit::Ok));
}

BOOST_AUTO_TEST_CASE(MintReplayCreditsOnce) {
  services::App app;
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  services::MintOp m = services::make_mint(v, app.mint_key(), bene, 4);
  const uint64_t one = app.mint_reward(pow_difficulty(m.solution)) - app.config().fee_mint;

  app.submit_mint(m);
  apply_block(app, 1);
  BOOST_TEST(app.balance(bene.pub) == one);

  app.submit_mint(m);
  apply_block(app, 2);
  BOOST_TEST(app.balance(bene.pub) == one);
}

BOOST_AUTO_TEST_CASE(BelowFloorMintDiscarded) {
  services::Config cfg;
  cfg.fee_mint = 1000000;
  cfg.reward_base = 1;
  services::App app(cfg);
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  services::MintOp m = services::make_mint(v, app.mint_key(), bene, /*min_diff=*/2);
  app.submit_mint(m);
  apply_block(app, 1);
  BOOST_TEST(!app.account_exists(bene.pub));
  BOOST_TEST(app.mint_seen_count() == 0u);
}

BOOST_AUTO_TEST_CASE(TamperedMintSignatureRejected) {
  services::App app;
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  services::MintOp m = services::make_mint(v, app.mint_key(), bene, 4);
  m.sig[0] ^= 0xff;
  app.submit_mint(m);
  apply_block(app, 1);
  BOOST_TEST(!app.account_exists(bene.pub));
}

BOOST_AUTO_TEST_CASE(SnapshotRestoreRoundTrips) {
  services::App app;
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  app.submit_mint(services::make_mint(v, app.mint_key(), bene, 4));
  apply_block(app, 1);
  const wire::Bytes snap = app.snapshot();

  services::App app2;
  app2.restore(wire::View(snap.data(), snap.size()));
  BOOST_TEST(app2.balance(bene.pub) == app.balance(bene.pub));
  BOOST_TEST(app2.mint_seen_count() == app.mint_seen_count());
  BOOST_TEST((app2.snapshot() == snap));

  wire::Bytes bad(snap.begin(), snap.end() - 1);
  BOOST_CHECK_THROW(app2.restore(wire::View(bad.data(), bad.size())), wire::Error);
  BOOST_TEST(app2.balance(bene.pub) == app.balance(bene.pub));
}

BOOST_AUTO_TEST_CASE(MintConvergesAcrossNodes) {
  std::vector<services::App> apps(4);
  std::vector<StateMachine*> sms;
  for (auto& a : apps) sms.push_back(&a);
  KeyPair bene = KeyPair::generate();
  Sha256PowVerifier v;
  apps[0].submit_mint(services::make_mint(v, apps[0].mint_key(), bene, 4));

  LocalCluster c(sms);
  c.run(8, 4);

  const uint64_t b0 = apps[0].balance(bene.pub);
  BOOST_TEST(b0 > 0u);
  for (int i = 1; i < 4; i++) BOOST_TEST(apps[i].balance(bene.pub) == b0);
  const Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; i++) BOOST_TEST((c.nodes[i]->composite_hash() == h0));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheTransfers)

BOOST_AUTO_TEST_CASE(TransferMovesCreditsBurnsFeeAdvancesSequence) {
  services::App app;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  Sha256PowVerifier v;
  app.submit_mint(services::make_mint(v, app.mint_key(), A, /*min_diff=*/6));
  apply_block(app, 1);
  const uint64_t funded = app.balance(A.pub);
  BOOST_REQUIRE(funded >= 21u);

  const wire::Bytes bkey = services::account_key(B.pub);
  app.submit_transfer(services::make_transfer(A, kv_view(bkey), 20, /*seq=*/0));
  apply_block(app, 2);

  BOOST_TEST(app.balance(A.pub) == funded - 20u - app.config().fee_transfer);
  BOOST_TEST(app.balance(B.pub) == 20u);
  BOOST_TEST(app.account_exists(B.pub));
  BOOST_TEST(app.sequence(A.pub) == 1u);
}

BOOST_AUTO_TEST_CASE(TransferReplayRejectedBySequence) {
  services::App app;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  Sha256PowVerifier v;
  app.submit_mint(services::make_mint(v, app.mint_key(), A, 6));
  apply_block(app, 1);
  const wire::Bytes bkey = services::account_key(B.pub);
  const services::TransferOp t = services::make_transfer(A, kv_view(bkey), 10, /*seq=*/0);

  app.submit_transfer(t);
  apply_block(app, 2);
  BOOST_TEST(app.balance(B.pub) == 10u);
  BOOST_TEST(app.sequence(A.pub) == 1u);

  app.submit_transfer(t);
  apply_block(app, 3);
  BOOST_TEST(app.balance(B.pub) == 10u);
  BOOST_TEST(app.sequence(A.pub) == 1u);
}

BOOST_AUTO_TEST_CASE(InsufficientTransferRejected) {
  services::App app;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  Sha256PowVerifier v;
  app.submit_mint(services::make_mint(v, app.mint_key(), A, 4));
  apply_block(app, 1);
  const uint64_t funded = app.balance(A.pub);

  const wire::Bytes bkey = services::account_key(B.pub);
  app.submit_transfer(services::make_transfer(A, kv_view(bkey), funded + 100, /*seq=*/0));
  apply_block(app, 2);
  BOOST_TEST(!app.account_exists(B.pub));
  BOOST_TEST(app.balance(A.pub) == funded);
  BOOST_TEST(app.sequence(A.pub) == 0u);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheEntries)

static uint64_t fund(services::App& app, const KeyPair& A, uint64_t height, unsigned diff = 8) {
  Sha256PowVerifier v;
  app.submit_mint(services::make_mint(v, app.mint_key(), A, diff));
  apply_block(app, height);
  return app.balance(A.pub);
}

BOOST_AUTO_TEST_CASE(EntryCreateHoldsOwnerBalancePayload) {
  services::App app;
  KeyPair A = KeyPair::generate();
  const uint64_t funded = fund(app, A, 1);

  app.submit_entry(services::make_entry_put(A, sv("foo"), /*seq=*/0, /*fund=*/50, sv("hello")));
  apply_block(app, 2);

  BOOST_TEST(app.entry_exists(sv("foo")));
  BOOST_TEST((app.entry_owner(sv("foo")) == A.pub));
  BOOST_TEST(app.entry_balance(sv("foo")) == 50u);
  const wire::Bytes pl = app.entry_payload(sv("foo"));
  BOOST_TEST(std::string(pl.begin(), pl.end()) == "hello");
  BOOST_TEST(app.balance(A.pub) == funded - 50u - app.config().fee_entry);
  BOOST_TEST(app.sequence(A.pub) == 1u);
}

BOOST_AUTO_TEST_CASE(EntryUpdateOnlyByOwner) {
  services::App app;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  fund(app, A, 1);
  fund(app, B, 2);
  app.submit_entry(services::make_entry_put(A, sv("foo"), 0, 10, sv("v1")));
  apply_block(app, 3);

  app.submit_entry(services::make_entry_put(B, sv("foo"), 0, 5, sv("evil")));
  apply_block(app, 4);
  const wire::Bytes pl1 = app.entry_payload(sv("foo"));
  BOOST_TEST(std::string(pl1.begin(), pl1.end()) == "v1");
  BOOST_TEST((app.entry_owner(sv("foo")) == A.pub));
  BOOST_TEST(app.sequence(B.pub) == 0u);

  app.submit_entry(services::make_entry_put(A, sv("foo"), 1, 7, sv("v2")));
  apply_block(app, 5);
  const wire::Bytes pl2 = app.entry_payload(sv("foo"));
  BOOST_TEST(std::string(pl2.begin(), pl2.end()) == "v2");
  BOOST_TEST(app.entry_balance(sv("foo")) == 17u);
}

BOOST_AUTO_TEST_CASE(EntryDelRefundsOwner) {
  services::App app;
  KeyPair A = KeyPair::generate();
  fund(app, A, 1);
  app.submit_entry(services::make_entry_put(A, sv("foo"), 0, 40, sv("x")));
  apply_block(app, 2);
  const uint64_t before = app.balance(A.pub);

  app.submit_entry(services::make_entry_del(A, sv("foo"), 1));
  apply_block(app, 3);
  BOOST_TEST(!app.entry_exists(sv("foo")));
  BOOST_TEST(app.balance(A.pub) == before + 40u - app.config().fee_entry);
}

BOOST_AUTO_TEST_CASE(EntryGiveTransfersOwnership) {
  services::App app;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  fund(app, A, 1);
  fund(app, B, 2);
  app.submit_entry(services::make_entry_put(A, sv("foo"), 0, 5, sv("x")));
  apply_block(app, 3);
  app.submit_entry(services::make_entry_give(A, sv("foo"), 1, B.pub));
  apply_block(app, 4);
  BOOST_TEST((app.entry_owner(sv("foo")) == B.pub));

  app.submit_entry(services::make_entry_put(B, sv("foo"), 0, 0, sv("bee")));
  apply_block(app, 5);
  const wire::Bytes pl = app.entry_payload(sv("foo"));
  BOOST_TEST(std::string(pl.begin(), pl.end()) == "bee");
}

BOOST_AUTO_TEST_CASE(RentStarvesEntryThenRipPaysCuller) {
  services::Config cfg;
  cfg.rent_rate = 1;
  services::App app(cfg);
  uint64_t clock = 100;
  app.set_now_fn([&] { return clock; });
  KeyPair A = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  fund(app, A, 1);
  app.submit_entry(services::make_entry_put(A, sv("foo"), 0, /*fund=*/5, sv("abc")));
  apply_block(app, 2);

  clock = 100000;
  app.submit_entry(services::make_entry_rip(sv("foo"), C.pub));
  apply_block(app, 3);
  BOOST_TEST(!app.entry_exists(sv("foo")));
  BOOST_TEST(app.balance(C.pub) == app.config().rip_bounty);
}

BOOST_AUTO_TEST_CASE(FreshEntryNotRippable) {
  services::App app;
  KeyPair A = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  fund(app, A, 1);
  app.submit_entry(services::make_entry_put(A, sv("foo"), 0, 0, sv("")));
  apply_block(app, 2);
  app.submit_entry(services::make_entry_rip(sv("foo"), C.pub));
  apply_block(app, 3);
  BOOST_TEST(app.entry_exists(sv("foo")));
  BOOST_TEST(!app.account_exists(C.pub));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheGenesis)

BOOST_AUTO_TEST_CASE(HashDeterministicOrderIndependentAndTextRoundTrips) {
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  services::Genesis g1;
  g1.chain_id = "testchain";
  g1.validators = {A.pub, B.pub};
  g1.allocations = {{A.pub, 100}, {B.pub, 50}};
  services::Genesis g2;
  g2.chain_id = "testchain";
  g2.validators = {B.pub, A.pub};
  g2.allocations = {{B.pub, 50}, {A.pub, 100}};
  BOOST_TEST((g1.hash() == g2.hash()));

  services::Genesis g3 = services::Genesis::parse(g1.to_text());
  BOOST_TEST((g3.hash() == g1.hash()));
}

BOOST_AUTO_TEST_CASE(ConfigWindowIsInsideTheHashAndRoundTrips) {
  KeyPair A = KeyPair::generate();
  auto mk = [&](uint64_t window) {
    services::Genesis g;
    g.chain_id = "wc";
    g.validators = {A.pub};
    g.config.pbts_window_secs = window;
    return g;
  };
  BOOST_TEST((mk(3600).hash() != mk(1800).hash()));
  services::Genesis rt = services::Genesis::parse(mk(1234).to_text());
  BOOST_TEST(rt.config.pbts_window_secs == 1234u);
  BOOST_TEST((rt.hash() == mk(1234).hash()));
}

BOOST_AUTO_TEST_CASE(ValidateCatchesBadGenesis) {
  KeyPair A = KeyPair::generate();
  std::string err;
  services::Genesis g;
  g.chain_id = "c";
  g.validators = {A.pub};
  BOOST_TEST(g.validate(err));

  g.chain_id = "";
  BOOST_TEST(!g.validate(err));
  g.chain_id = "bad\"id";
  BOOST_TEST(!g.validate(err));
  g.chain_id = "c";
  g.validators.clear();
  BOOST_TEST(!g.validate(err));
  g.validators = {A.pub, A.pub};
  BOOST_TEST(!g.validate(err));
  g.validators = {A.pub};
  g.config.reward_base = 1;
  g.config.fee_mint = UINT64_MAX;
  BOOST_TEST(!g.validate(err));

  g.config = {};
  g.config.reward_base = 1;
  g.config.fee_mint = 1;
  BOOST_TEST(!g.validate(err));

  g.config = {};
  KeyPair B = KeyPair::generate();
  g.allocations = {{B.pub, 10}, {B.pub, 20}};
  BOOST_TEST(!g.validate(err));
  g.allocations.clear();

  g.config = {};
  g.config.rip_bounty = 10;
  g.config.rent_rate = 0;
  BOOST_TEST(g.validate(err));
  g.config.rent_rate = 5;
  BOOST_TEST(!g.validate(err));
  g.config.rip_bounty = 1;
  BOOST_TEST(g.validate(err));
}

BOOST_AUTO_TEST_CASE(AppFromGenesisSeedsAllocations) {
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "c";
  g.validators = {A.pub};
  g.allocations = {{A.pub, 1000}, {B.pub, 500}};
  services::App app = services::App::from_genesis(g);
  BOOST_TEST(app.balance(A.pub) == 1000u);
  BOOST_TEST(app.balance(B.pub) == 500u);
  BOOST_TEST(app.account_exists(A.pub));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheKeys)

BOOST_AUTO_TEST_CASE(KeyFileRoundTrips) {
  const std::string path = "/tmp/morphe_keytest.key";
  KeyPair kp = KeyPair::generate();
  services::save_key(path, kp);
  KeyPair loaded = services::load_key(path);
  BOOST_TEST((loaded.pub == kp.pub));
  BOOST_TEST((loaded.priv == kp.priv));
  BOOST_TEST(services::pubkey_hex(kp.pub).size() == 64u);
  std::remove(path.c_str());
}

BOOST_AUTO_TEST_CASE(LoadRejectsMissingFile) {
  BOOST_CHECK_THROW(services::load_key("/tmp/morphe_nonexistent_key_zzz"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(KeyringNamesAndPaths) {
  BOOST_TEST(services::valid_key_name("alice"));
  BOOST_TEST(services::valid_key_name("node-0_v.2"));
  BOOST_TEST(!services::valid_key_name(""));
  BOOST_TEST(!services::valid_key_name("."));
  BOOST_TEST(!services::valid_key_name(".."));
  BOOST_TEST(!services::valid_key_name("a/b"));
  BOOST_TEST(!services::valid_key_name("a b"));
  BOOST_CHECK_THROW(services::key_path("bad/name"), std::runtime_error);

  services::set_keyring_dir("/tmp/morphe_keyring_test");
  std::filesystem::remove_all("/tmp/morphe_keyring_test");
  const std::string p = services::key_path("alice");
  BOOST_TEST(p == "/tmp/morphe_keyring_test/alice.key");
  std::filesystem::create_directories("/tmp/morphe_keyring_test");
  KeyPair kp = KeyPair::generate();
  services::save_key(p, kp);
  services::save_key(services::key_path("bob"), KeyPair::generate());
  BOOST_TEST((services::load_key(p).pub == kp.pub));
  const std::vector<std::string> names = services::list_key_names();
  BOOST_TEST(names.size() == 2u);
  BOOST_TEST(names[0] == "alice");
  BOOST_TEST(names[1] == "bob");
  std::filesystem::remove_all("/tmp/morphe_keyring_test");
  services::set_keyring_dir("");
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheRuntime)

BOOST_AUTO_TEST_CASE(SingleValidatorAdvancesAndCommitsOps) {
  PrivKey secret{};
  secret[0] = 7;
  KeyPair v = KeyPair::from_secret(secret);
  services::Genesis g;
  g.chain_id = "rt";
  g.validators = {v.pub};
  services::Runtime rt(g, v, {/*block_pace_ms=*/0});

  rt.run_to(3);
  BOOST_TEST(rt.height() >= 3u);

  KeyPair A = KeyPair::generate();
  Sha256PowVerifier pv;
  rt.app().submit_mint(services::make_mint(pv, rt.app().mint_key(), A, 4, 0, sv(g.chain_id)));
  rt.run_to(rt.height() + 3);
  BOOST_TEST(rt.app().balance(A.pub) > 0u);
}

BOOST_AUTO_TEST_CASE(OutOfWindowTimestampRejected) {
  services::App app;
  uint64_t clock = 1'000'000;
  app.set_now_fn([&] { return clock; });

  services::Decoded d;
  d.timestamp = clock;
  const wire::Bytes ok = services::encode_ops(d);
  BOOST_TEST(app.validate_payload(wire::View(ok.data(), ok.size())));

  d.timestamp = clock + app.config().pbts_window_secs + 100;
  const wire::Bytes future = services::encode_ops(d);
  BOOST_TEST(!app.validate_payload(wire::View(future.data(), future.size())));

  d.timestamp = clock - app.config().pbts_window_secs - 100;
  const wire::Bytes past = services::encode_ops(d);
  BOOST_TEST(!app.validate_payload(wire::View(past.data(), past.size())));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheFrame)

BOOST_AUTO_TEST_CASE(FrameRoundTrips) {
  KeyPair dst = KeyPair::generate();
  KeyPair src = KeyPair::generate();
  const char* pl = "hello mesh";
  wire::View payload(reinterpret_cast<const uint8_t*>(pl), std::strlen(pl));

  morphe::FrameHeader h;
  h.chain_tag = morphe::chain_tag_of(sv("mychain"));
  h.type = services::MsgType::Consensus;
  h.channel = static_cast<uint8_t>(services::Channel::Consensus);
  h.hop_count = 1;
  h.flags = morphe::FLAG_FORWARD;
  h.dest = dst.pub;
  h.src = src.pub;
  h.msg_id = morphe::make_msg_id(src.pub, dst.pub, payload);

  const wire::Bytes framed = morphe::encode_frame(h, payload);
  BOOST_TEST(framed.size() == morphe::FRAME_HEADER_SIZE + payload.size());

  morphe::FrameHeader got;
  wire::View got_payload = morphe::decode_frame(wire::View(framed.data(), framed.size()), got);
  BOOST_TEST(got.version == morphe::PROTOCOL_VERSION);
  BOOST_TEST(got.chain_tag == h.chain_tag);
  BOOST_TEST((got.type == services::MsgType::Consensus));
  BOOST_TEST(got.hop_count == 1);
  BOOST_TEST(got.flags == morphe::FLAG_FORWARD);
  BOOST_TEST((got.dest == dst.pub));
  BOOST_TEST((got.src == src.pub));
  BOOST_TEST((got.msg_id == h.msg_id));
  BOOST_TEST(std::string(got_payload.begin(), got_payload.end()) == "hello mesh");
}

BOOST_AUTO_TEST_CASE(FrameRejectsMalformed) {
  morphe::FrameHeader h;
  h.type = services::MsgType::Ping;
  const wire::Bytes good = morphe::encode_frame(h, wire::View{});
  morphe::FrameHeader got;

  wire::Bytes bad_magic = good;
  bad_magic[0] ^= 0xff;
  BOOST_CHECK_THROW(morphe::decode_frame(wire::View(bad_magic.data(), bad_magic.size()), got),
                    wire::Error);

  wire::Bytes trailing = good;
  trailing.push_back(0x00);
  BOOST_CHECK_THROW(morphe::decode_frame(wire::View(trailing.data(), trailing.size()), got),
                    wire::Error);

  wire::Bytes truncated(good.begin(), good.end() - 1);
  BOOST_CHECK_THROW(morphe::decode_frame(wire::View(truncated.data(), truncated.size()), got),
                    wire::Error);
}

BOOST_AUTO_TEST_CASE(SeenCacheDedupsAndEvicts) {
  morphe::SeenCache cache(2);
  morphe::MsgId a{}, b{}, c{};
  a[0] = 1;
  b[0] = 2;
  c[0] = 3;
  BOOST_TEST(cache.insert(a));
  BOOST_TEST(!cache.insert(a));
  BOOST_TEST(cache.insert(b));
  BOOST_TEST(cache.insert(c));
  BOOST_TEST(cache.size() == 2u);
  BOOST_TEST(cache.insert(a));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheMesh)

struct MeshFixture {
  KeyPair A = KeyPair::generate(), B = KeyPair::generate(), C = KeyPair::generate();
  morphe::SimMesh mesh;
  morphe::SimMeshPort pa{&mesh, A.pub}, pb{&mesh, B.pub}, pc{&mesh, C.pub};
  MeshFixture() { mesh.init({A.pub, B.pub, C.pub}); }
};

BOOST_FIXTURE_TEST_CASE(RoutesDirectDelivers, MeshFixture) {
  bool got = false;
  pb.on_recv = [&](const PubKey&, services::MsgType, wire::View) { got = true; };
  mesh.route(A.pub, B.pub, services::MsgType::Consensus, sv("hi"));
  BOOST_TEST(got);
  BOOST_TEST(mesh.delivered == 1u);
  BOOST_TEST(mesh.relay_count == 0u);
}

BOOST_FIXTURE_TEST_CASE(ForwardingRequiredUsesRelay, MeshFixture) {
  mesh.down(A.pub, C.pub);
  bool got = false;
  pc.on_recv = [&](const PubKey&, services::MsgType, wire::View) { got = true; };
  mesh.route(A.pub, C.pub, services::MsgType::Consensus, sv("relayme"));
  BOOST_TEST(got);
  BOOST_TEST(mesh.relay_count > 0u);
}

BOOST_FIXTURE_TEST_CASE(StrandedNodeUnreachable, MeshFixture) {
  mesh.down(A.pub, C.pub);
  mesh.down(B.pub, C.pub);
  bool got = false;
  pc.on_recv = [&](const PubKey&, services::MsgType, wire::View) { got = true; };
  mesh.route(A.pub, C.pub, services::MsgType::Consensus, sv("lost"));
  BOOST_TEST(!got);
  BOOST_TEST(mesh.dropped_no_relay > 0u);
}

BOOST_FIXTURE_TEST_CASE(SeenCacheDedupsRedundantDelivery, MeshFixture) {
  int count = 0;
  pb.on_recv = [&](const PubKey&, services::MsgType, wire::View) { ++count; };
  mesh.route(A.pub, B.pub, services::MsgType::Tx, sv("dup"));
  mesh.route(A.pub, B.pub, services::MsgType::Tx, sv("dup"));
  BOOST_TEST(count == 1);
  BOOST_TEST(mesh.seen_drop > 0u);
}

BOOST_FIXTURE_TEST_CASE(PeerMapChurnRecovers, MeshFixture) {
  mesh.down(A.pub, C.pub);
  pc.on_recv = [&](const PubKey&, services::MsgType, wire::View) {};
  mesh.route(A.pub, C.pub, services::MsgType::Consensus, sv("m1"));
  BOOST_TEST(mesh.relay_count > 0u);
  const uint64_t relays_before = mesh.relay_count;

  mesh.up(A.pub, C.pub);
  mesh.route(A.pub, C.pub, services::MsgType::Consensus, sv("m2"));
  BOOST_TEST(mesh.relay_count == relays_before);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheMeshConsensus)

static services::Genesis mesh_g(int n) { return morphe::mesh_genesis(morphe::mesh_keys(n)); }

BOOST_AUTO_TEST_CASE(ConvergesFullMesh) {
  morphe::MorpheMeshCluster c(4, mesh_g(4));
  BOOST_TEST(c.run(/*goal=*/3, /*needed=*/4));
  BOOST_TEST(c.committed(3) == 4);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(ConvergesUnderRelay) {
  morphe::MorpheMeshCluster c(4, mesh_g(4));
  c.down(0, 1);
  c.down(2, 3);
  BOOST_TEST(c.run(/*goal=*/3, /*needed=*/4));
  BOOST_TEST(c.relay_used > 0u);
  BOOST_TEST(c.committed(3) == 4);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(PartitionedMinorityDoesNotStallQuorum) {
  morphe::MorpheMeshCluster c(4, mesh_g(4));
  c.isolate(3);
  BOOST_TEST(c.run(/*goal=*/3, /*needed=*/3));
  BOOST_TEST(c.partition_drop > 0u);
  BOOST_TEST(c.committed(3) == 3);
  BOOST_TEST(c.nodes[3]->applied_height() < 3u);
}

BOOST_AUTO_TEST_CASE(PartitionHealsLaggardRecovers) {
  morphe::MorpheMeshCluster c(4, mesh_g(4));
  c.isolate(3);
  bool healed = false;
  auto hook = [&healed](morphe::MorpheMeshCluster& cl, uint64_t iters) {
    if (!healed && iters >= 40) { cl.reconnect(3); healed = true; }
  };
  BOOST_TEST(c.run(/*goal=*/4, /*needed=*/4, /*max_events=*/4000000, hook));
  BOOST_TEST(c.partition_drop > 0u);
  BOOST_TEST(healed);
  BOOST_TEST(c.committed(4) == 4);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(ConvergesUnderPacketLoss) {
  morphe::MorpheMeshCluster c(4, mesh_g(4), /*seed=*/7);
  c.loss_pct = 25;
  BOOST_TEST(c.run(/*goal=*/3, /*needed=*/4));
  BOOST_TEST(c.loss_drop > 0u);
  BOOST_TEST(c.committed(3) == 4);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheMeshFaults)

static services::Genesis mesh_g(int n) { return morphe::mesh_genesis(morphe::mesh_keys(n)); }

BOOST_AUTO_TEST_CASE(CrashedMinorityQuorumKeepsCommitting) {
  morphe::MorpheMeshCluster c(4, mesh_g(4));
  c.deactivate(3);
  BOOST_TEST(c.run(/*goal=*/4, /*needed=*/3));
  BOOST_TEST(c.committed(4) == 3);
  BOOST_TEST(c.nodes[3]->applied_height() == 0u);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(CrashedNodeRestartsAndCatchesUp) {
  morphe::MorpheMeshCluster c(4, mesh_g(4));
  const int dead = 3;
  uint64_t behind_gap = 0;
  bool killed = false, restarted = false;
  auto survivor_tip = [&](morphe::MorpheMeshCluster& cl) {
    uint64_t tip = 0;
    for (int i = 0; i < 4; i++)
      if (i != dead && cl.nodes[i]->applied_height() > tip) tip = cl.nodes[i]->applied_height();
    return tip;
  };
  auto hook = [&](morphe::MorpheMeshCluster& cl, uint64_t iters) {
    if (!killed && iters >= 2) { cl.deactivate(dead); killed = true; }
    if (killed && !restarted && survivor_tip(cl) >= 4) {
      behind_gap = survivor_tip(cl) - cl.nodes[dead]->applied_height();
      cl.reactivate(dead);
      restarted = true;
    }
  };
  BOOST_TEST(c.run(/*goal=*/5, /*needed=*/4, /*max_events=*/8000000, hook));
  BOOST_TEST(killed);
  BOOST_TEST(restarted);
  BOOST_TEST(behind_gap > 0u);
  BOOST_TEST(c.committed(5) == 4);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_CASE(LargeSetConvergesUnderSustainedLoss) {
  morphe::MorpheMeshCluster c(7, mesh_g(7), /*seed=*/11);
  c.loss_pct = 20;
  BOOST_TEST(c.run(/*goal=*/3, /*needed=*/7, /*max_events=*/20000000));
  BOOST_TEST(c.loss_drop > 0u);
  BOOST_TEST(c.committed(3) == 7);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheMempool)

static wire::Bytes acct_key(const PubKey& pk) {
  wire::Bytes b;
  b.push_back(services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}

BOOST_AUTO_TEST_CASE(AdmitsValidTransfer) {
  services::Mempool mp{services::Config{}};
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  wire::Bytes to = acct_key(b.pub);
  services::TransferOp op = services::make_transfer(a, kv_view(to), 10, /*seq=*/0);
  BOOST_TEST((mp.admit_transfer(op, /*committed_seq=*/0, /*balance=*/100) == services::Admit::Ok));
  BOOST_TEST(mp.size() == 1u);
}

BOOST_AUTO_TEST_CASE(RejectsBadShapeSigSeqFunds) {
  services::Config cfg;
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  wire::Bytes to = acct_key(b.pub);

  {
    services::Mempool mp{cfg};
    services::TransferOp op = services::make_transfer(a, kv_view(to), 10, 0);
    op.to.pop_back();
    BOOST_TEST((mp.admit_transfer(op, 0, 100) == services::Admit::BadShape));
  }
  {
    services::Mempool mp{cfg};
    services::TransferOp op = services::make_transfer(a, kv_view(to), 10, 0);
    op.sig[0] ^= 0xFF;
    BOOST_TEST((mp.admit_transfer(op, 0, 100) == services::Admit::BadSig));
  }
  {
    services::Mempool mp{cfg};
    services::TransferOp op = services::make_transfer(a, kv_view(to), 10, /*seq=*/5);
    BOOST_TEST((mp.admit_transfer(op, /*committed_seq=*/0, 100) == services::Admit::SeqGap));
  }
  {
    services::Mempool mp{cfg};
    services::TransferOp ok = services::make_transfer(a, kv_view(to), 10, 0);
    BOOST_TEST((mp.admit_transfer(ok, 0, 100) == services::Admit::Ok));
    services::TransferOp stale = services::make_transfer(a, kv_view(to), 20, /*seq=*/0);
    BOOST_TEST((mp.admit_transfer(stale, 0, 100) == services::Admit::SeqStale));
  }
  {
    services::Mempool mp{cfg};
    services::TransferOp op = services::make_transfer(a, kv_view(to), 10, 0);
    BOOST_TEST((mp.admit_transfer(op, 0, /*balance=*/5) == services::Admit::InsufficientFunds));
  }
}

BOOST_AUTO_TEST_CASE(DedupAndCapacity) {
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  wire::Bytes to = acct_key(b.pub);
  {
    services::Mempool mp{services::Config{}};
    services::TransferOp op = services::make_transfer(a, kv_view(to), 10, 0);
    BOOST_TEST((mp.admit_transfer(op, 0, 100) == services::Admit::Ok));
    BOOST_TEST((mp.admit_transfer(op, 0, 100) == services::Admit::Duplicate));
  }
  {
    services::Mempool mp{services::Config{}, /*capacity=*/1};
    services::TransferOp op0 = services::make_transfer(a, kv_view(to), 10, 0);
    services::TransferOp op1 = services::make_transfer(a, kv_view(to), 10, 1);
    BOOST_TEST((mp.admit_transfer(op0, 0, 100) == services::Admit::Ok));
    BOOST_TEST((mp.admit_transfer(op1, 0, 100) == services::Admit::Full));
  }
}

BOOST_AUTO_TEST_CASE(ChainedNoncesAndDrainOrder) {
  services::Mempool mp{services::Config{}};
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  wire::Bytes to = acct_key(b.pub);
  services::TransferOp t0 = services::make_transfer(a, kv_view(to), 10, 0);
  services::TransferOp t1 = services::make_transfer(a, kv_view(to), 10, 1);
  BOOST_TEST((mp.admit_transfer(t0, 0, 100) == services::Admit::Ok));
  BOOST_TEST((mp.admit_transfer(t1, 0, 100) == services::Admit::Ok));
  services::TransferOp t2 = services::make_transfer(a, kv_view(to), 100, 2);
  BOOST_TEST((mp.admit_transfer(t2, 0, 100) == services::Admit::InsufficientFunds));

  services::Decoded d = mp.drain(10);
  BOOST_TEST(d.transfers.size() == 2u);
  BOOST_TEST(d.transfers[0].seq == 0u);
  BOOST_TEST(d.transfers[1].seq == 1u);
  BOOST_TEST(mp.empty());
}

BOOST_AUTO_TEST_CASE(MintAdmissionFloorAndDedup) {
  services::Config cfg;
  services::Mempool mp{cfg};
  Sha256PowVerifier v;
  Hash key{};
  KeyPair ben = KeyPair::generate();
  services::MintOp good = services::make_mint(v, key, ben, /*min_diff=*/1);
  BOOST_TEST((mp.admit_mint(good) == services::Admit::Ok));
  BOOST_TEST((mp.admit_mint(good) == services::Admit::Duplicate));

  services::MintOp junk = good;
  junk.solution.fill(0xFF);
  BOOST_TEST((mp.admit_mint(junk) == services::Admit::BelowFloor));
}

BOOST_AUTO_TEST_CASE(AdmittedTransferCommitsAndMovesBalance) {
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "mp";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 1000}};
  services::App app = services::App::from_genesis(g);

  wire::Bytes to = acct_key(b.pub);
  services::TransferOp op = services::make_transfer(a, kv_view(to), 100, /*seq=*/0, sv(g.chain_id));
  BOOST_TEST((app.admit_transfer(op) == services::Admit::Ok));
  BOOST_TEST(app.mempool().size() == 1u);

  apply_block(app, 1);

  BOOST_TEST(app.balance(b.pub) == 100u);
  BOOST_TEST(app.balance(a.pub) == 1000u - 100u - 1u);
  BOOST_TEST(app.sequence(a.pub) == 1u);
  BOOST_TEST(app.mempool().empty());
}

BOOST_AUTO_TEST_CASE(AdmittedTransferCommitsChainWide) {
  auto kps = morphe::mesh_keys(4);
  services::Genesis g = morphe::mesh_genesis(kps);
  g.allocations = {{kps[0].pub, 1000}};
  morphe::MorpheMeshCluster c(4, g);

  wire::Bytes to = acct_key(kps[1].pub);
  services::TransferOp op = services::make_transfer(kps[0], kv_view(to), 100, /*seq=*/0, sv(g.chain_id));
  for (int i = 0; i < 4; i++) BOOST_TEST((c.apps[i]->admit_transfer(op) == services::Admit::Ok));

  BOOST_TEST(c.run(/*goal=*/2, /*needed=*/4));
  for (int i = 0; i < 4; i++) {
    BOOST_TEST(c.apps[i]->balance(kps[1].pub) == 100u);
    BOOST_TEST(c.apps[i]->balance(kps[0].pub) == 1000u - 101u);
  }
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheNetRuntime)

BOOST_AUTO_TEST_CASE(FourRuntimesCommitOverMesh) {
  auto kps = morphe::mesh_keys(4);
  services::Genesis g = morphe::mesh_genesis(kps);
  morphe::SimMesh mesh;
  mesh.init(g.validators);

  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<services::Runtime>> rts;
  for (int i = 0; i < 4; i++)
    ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 4; i++)
    rts.push_back(std::make_unique<services::Runtime>(g, kps[i], services::NodeOptions{/*pace=*/0}, ports[i].get()));

  for (auto& rt : rts) rt->begin();
  const uint64_t GOAL = 3;
  bool reached = false;
  for (int iter = 0; iter < 200000 && !reached; ++iter) {
    bool progress = false;
    for (auto& rt : rts) if (rt->pump()) progress = true;
    for (auto& rt : rts) if (rt->advance()) progress = true;
    if (!progress)
      for (auto& rt : rts) rt->fire_one_timeout();
    reached = true;
    for (auto& rt : rts) if (rt->height() < GOAL) reached = false;
  }

  for (auto& rt : rts) BOOST_TEST(rt->height() >= GOAL);
  Hash ref = rts[0]->node().composite_hash();
  for (auto& rt : rts)
    BOOST_TEST((rt->node().composite_hash() == ref));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorphePropagation)

static wire::Bytes acct_key_p(const PubKey& pk) {
  wire::Bytes b;
  b.push_back(services::ACCOUNT_PREFIX);
  b.insert(b.end(), pk.begin(), pk.end());
  return b;
}

BOOST_AUTO_TEST_CASE(SubmittedTxFloodsAndCommitsChainWide) {
  auto kps = morphe::mesh_keys(4);
  services::Genesis g = morphe::mesh_genesis(kps);
  g.allocations = {{kps[0].pub, 1000}};
  morphe::SimMesh mesh;
  mesh.init(g.validators);
  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<services::Runtime>> rts;
  for (int i = 0; i < 4; i++)
    ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 4; i++)
    rts.push_back(std::make_unique<services::Runtime>(g, kps[i], services::NodeOptions{/*pace=*/0}, ports[i].get()));

  wire::Bytes to = acct_key_p(kps[1].pub);
  services::TransferOp op = services::make_transfer(kps[0], kv_view(to), 100, /*seq=*/0, sv(g.chain_id));
  BOOST_TEST((rts[0]->submit(op) == services::Admit::Ok));
  for (int i = 0; i < 4; i++)
    BOOST_TEST(rts[i]->app().mempool().size() == 1u);

  for (auto& rt : rts) rt->begin();
  const uint64_t GOAL = 2;
  bool reached = false;
  for (int iter = 0; iter < 200000 && !reached; ++iter) {
    bool progress = false;
    for (auto& rt : rts) if (rt->pump()) progress = true;
    for (auto& rt : rts) if (rt->advance()) progress = true;
    if (!progress) for (auto& rt : rts) rt->fire_one_timeout();
    reached = true;
    for (auto& rt : rts) if (rt->height() < GOAL) reached = false;
  }
  for (int i = 0; i < 4; i++)
    BOOST_TEST(rts[i]->app().balance(kps[1].pub) == 100u);
}

BOOST_AUTO_TEST_CASE(PropagationReachesAllUnderLoss) {
  auto kps = morphe::mesh_keys(5);
  services::Genesis g = morphe::mesh_genesis(kps);
  g.allocations = {{kps[0].pub, 1000}};
  morphe::SimMesh mesh;
  mesh.init(g.validators);
  mesh.loss_pct = 40;
  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<services::Runtime>> rts;
  for (int i = 0; i < 5; i++)
    ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 5; i++)
    rts.push_back(std::make_unique<services::Runtime>(g, kps[i], services::NodeOptions{/*pace=*/0}, ports[i].get()));

  wire::Bytes to = acct_key_p(kps[1].pub);
  services::TransferOp op = services::make_transfer(kps[0], kv_view(to), 100, 0, sv(g.chain_id));
  rts[0]->submit(op);

  bool all = false;
  for (int iter = 0; iter < 100000 && !all; ++iter) {
    for (auto& rt : rts) rt->regossip();
    all = true;
    for (auto& rt : rts) if (rt->app().mempool().empty()) all = false;
  }
  BOOST_TEST(all);
  BOOST_TEST(mesh.lost > 0u);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheFuzz)

struct FRng {
  uint64_t s;
  uint64_t next() {
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  uint32_t below(uint32_t n) { return n ? static_cast<uint32_t>(next() % n) : 0; }
};

static wire::Bytes rand_bytes(FRng& r, size_t maxlen) {
  const size_t n = r.below(static_cast<uint32_t>(maxlen) + 1);
  wire::Bytes b(n);
  for (size_t i = 0; i < n; ++i) b[i] = static_cast<uint8_t>(r.next() & 0xff);
  return b;
}

template <class Decode>
static void fuzz_bytes(uint64_t seed, const wire::Bytes& valid, Decode decode) {
  FRng r{seed};
  int rejected = 0, ok = 0;
  for (int i = 0; i < 10000; ++i) {
    wire::Bytes b;
    if (i % 2 == 0 || valid.empty()) {
      b = rand_bytes(r, 128);
    } else {
      b = valid;
      const uint32_t kind = r.below(3);
      if (kind == 0 && !b.empty()) b[r.below(b.size())] ^= static_cast<uint8_t>(1u << r.below(8));
      else if (kind == 1 && !b.empty()) b.resize(r.below(b.size()));
      else b.push_back(static_cast<uint8_t>(r.next()));
    }
    try {
      decode(wire::View(b.data(), b.size()));
      ++ok;
    } catch (const std::exception&) {
      ++rejected;
    }
  }
  BOOST_TEST(rejected > 0);
}

BOOST_AUTO_TEST_CASE(FuzzDecodeFrame) {
  auto kps = morphe::mesh_keys(1);
  morphe::FrameHeader h;
  h.chain_tag = 7;
  h.type = services::MsgType::Consensus;
  h.dest = kps[0].pub;
  h.src = kps[0].pub;
  const wire::Bytes valid = morphe::encode_frame(h, sv("hello"));
  fuzz_bytes(0x1111, valid, [](wire::View v) { morphe::FrameHeader out; morphe::decode_frame(v, out); });
}

BOOST_AUTO_TEST_CASE(FuzzDecodeOps) {
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  wire::Bytes to = rpc_acct_key(b.pub);
  services::Decoded d;
  d.timestamp = 123;
  d.transfers.push_back(services::make_transfer(a, kv_view(to), 5, 0));
  const wire::Bytes valid = services::encode_ops(d);
  fuzz_bytes(0x2222, valid, [](wire::View v) { services::decode_ops(v); });
}

BOOST_AUTO_TEST_CASE(FuzzSnapshotRestore) {
  services::Genesis g;
  g.chain_id = "fz";
  g.validators = {KeyPair::generate().pub};
  services::App app = services::App::from_genesis(g);
  const wire::Bytes valid = app.snapshot();
  fuzz_bytes(0x3333, valid, [&](wire::View v) { app.restore(v); });
}

BOOST_AUTO_TEST_CASE(FuzzGenesisParse) {
  FRng r{0x4444};
  int rejected = 0;
  const char* toks[] = {"chain_id", "validator", "alloc", "fee_mint", "x", "\n", " ", "deadbeef", "42"};
  for (int i = 0; i < 10000; ++i) {
    std::string s;
    const int words = 1 + r.below(8);
    for (int w = 0; w < words; ++w) { s += toks[r.below(9)]; s += (r.below(2) ? " " : "\n"); }
    try { services::Genesis::parse(s); } catch (const std::exception&) { ++rejected; }
  }
  BOOST_TEST(rejected > 0);
}

BOOST_AUTO_TEST_CASE(FuzzRpcDispatch) {
  services::Genesis g;
  g.chain_id = "fz";
  g.validators = {KeyPair::generate().pub};
  services::Runtime rt(g, KeyPair::generate());
  morphe::RpcService svc(rt);
  const char* methods[] = {"submit_tx", "query.balance", "query.tx", "admin.leave",
                           "query.entry", "status", "no.such", "query.account"};
  FRng r{0x5555};
  int handled = 0;
  for (int i = 0; i < 10000; ++i) {
    json::object p;
    if (r.below(2)) p["pubkey"] = std::string(r.below(80), 'a' + static_cast<char>(r.below(6)));
    if (r.below(2)) p["tx"] = std::string(r.below(40), '0' + static_cast<char>(r.below(20)));
    if (r.below(2)) p["token"] = "tok";
    if (r.below(2)) p["name"] = "zz";
    try { svc.handle(methods[r.below(8)], p); }
    catch (const morphe::RpcError&) { ++handled; }
    catch (const std::exception&) { ++handled; }
  }
  BOOST_TEST(handled > 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheDeterminism)

BOOST_AUTO_TEST_CASE(SameInputsIdenticalAppHash) {
  auto kps = morphe::mesh_keys(4);
  services::Genesis g = morphe::mesh_genesis(kps);
  g.allocations = {{kps[0].pub, 1000}};

  auto run_once = [&](uint64_t seed) -> Hash {
    morphe::MorpheMeshCluster c(4, g, seed);
    for (int i = 0; i < 4; i++) c.apps[i]->set_now_fn([] { return uint64_t{1'700'000'000}; });
    wire::Bytes to = rpc_acct_key(kps[1].pub);
    services::TransferOp op = services::make_transfer(kps[0], kv_view(to), 100, 0, sv(g.chain_id));
    for (int i = 0; i < 4; i++) c.apps[i]->admit_transfer(op);
    c.run(/*goal=*/3, /*needed=*/4);
    return c.nodes[0]->composite_hash();
  };

  const Hash ref = run_once(1);
  for (uint64_t seed = 2; seed <= 5; ++seed)
    BOOST_TEST((run_once(seed) == ref));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheReview)

BOOST_AUTO_TEST_CASE(MsgIdIncludesDest) {
  auto kps = morphe::mesh_keys(3);
  const char* pl = "payload";
  wire::View v(reinterpret_cast<const uint8_t*>(pl), std::strlen(pl));
  morphe::MsgId to_b = morphe::make_msg_id(kps[0].pub, kps[1].pub, v);
  morphe::MsgId to_c = morphe::make_msg_id(kps[0].pub, kps[2].pub, v);
  BOOST_TEST((to_b != to_c));
  BOOST_TEST((morphe::make_msg_id(kps[0].pub, kps[1].pub, v) == to_b));
}

BOOST_AUTO_TEST_CASE(EmptyNameEntryIsNoOp) {
  KeyPair owner = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "rev";
  g.validators = {owner.pub};
  g.allocations = {{owner.pub, 1000}};
  services::App app = services::App::from_genesis(g);

  services::Decoded d;
  d.timestamp = 1;
  d.entries.push_back(services::make_entry_put(owner, wire::View{}, 0, 10, wire::View{}));
  wire::Bytes p = services::encode_ops(d);
  app.apply_payload(ApplyContext{1, PubKey{}}, kv_view(p));

  BOOST_TEST(!app.entry_exists(wire::View{}));
  BOOST_TEST(app.balance(owner.pub) == 1000u);
}

static wire::Bytes ekey(const char* name) {
  wire::Bytes b;
  b.push_back(services::ENTRY_PREFIX);
  b.insert(b.end(), name, name + std::strlen(name));
  return b;
}

BOOST_AUTO_TEST_CASE(TransferCreatesFundsAndTopsUpEntry) {
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "te";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 1000}, {b.pub, 500}};
  services::App app = services::App::from_genesis(g);

  wire::Bytes dst = ekey("rec1");
  BOOST_TEST((app.admit_transfer(services::make_transfer(a, kv_view(dst), 100, 0, sv(g.chain_id))) == services::Admit::Ok));
  apply_block(app, 1);
  wire::View name(reinterpret_cast<const uint8_t*>("rec1"), 4);
  BOOST_TEST(app.entry_exists(name));
  BOOST_TEST((app.entry_owner(name) == a.pub));
  BOOST_TEST(app.entry_balance(name) == 100u);
  BOOST_TEST(app.balance(a.pub) == 1000u - 100u - 1u);

  BOOST_TEST((app.admit_transfer(services::make_transfer(b, kv_view(dst), 50, 0, sv(g.chain_id))) == services::Admit::Ok));
  apply_block(app, 2);
  BOOST_TEST(app.entry_balance(name) == 150u);
  BOOST_TEST((app.entry_owner(name) == a.pub));
  BOOST_TEST(app.balance(b.pub) == 500u - 50u - 1u);
}

BOOST_AUTO_TEST_CASE(TransferToEmptyEntryKeyRejected) {
  KeyPair a = KeyPair::generate();
  wire::Bytes bare;
  bare.push_back(services::ENTRY_PREFIX);
  services::TransferOp op = services::make_transfer(a, kv_view(bare), 10, 0);
  services::Mempool mp{services::Config{}};
  BOOST_TEST((mp.admit_transfer(op, 0, 1000) == services::Admit::BadShape));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheLifecycle)

static services::Genesis life_g(int n) { return morphe::mesh_genesis(morphe::mesh_keys(n)); }

// Encode a signed Prop: [u64 h][u64 round][proposer:32][bytes value][sig:64]. claimed is the
// proposer field; signer is who actually signs.
static wire::Bytes make_prop_as(uint64_t h, int64_t round, const PubKey& claimed, const KeyPair& signer,
                                const char* value, const std::string& chain_id = "morphe-mesh") {
  wire::View vv = sv(value);
  wire::Bytes sb;  // sign bytes: "MORPHE_PROP_V1" || chain_id || h || round || sha256(value)
  {
    wire::Writer sw(sb);
    sw.raw(wire::View(reinterpret_cast<const uint8_t*>("MORPHE_PROP_V1"), 14));
    sw.bytes(sv(chain_id));
    sw.u64(h);
    sw.u64(static_cast<uint64_t>(round));
    Hash vh = sha256(vv);
    sw.raw(wire::View(vh.data(), vh.size()));
  }
  Sig sig = signer.sign(wire::View(sb.data(), sb.size()));
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(h);
  w.u64(static_cast<uint64_t>(round));
  w.raw(wire::View(claimed.data(), claimed.size()));
  w.bytes(vv);
  w.raw(wire::View(sig.data(), sig.size()));
  return out;
}
static wire::Bytes make_prop(uint64_t h, int64_t round, const KeyPair& proposer, const char* value) {
  return make_prop_as(h, round, proposer.pub, proposer, value);
}

BOOST_AUTO_TEST_CASE(DoubleSignEvidenceWritten) {
  namespace fs = std::filesystem;
  auto kps = morphe::mesh_keys(2);
  services::Genesis g = morphe::mesh_genesis(kps);
  services::Runtime rt(g, kps[0]);
  const std::string dir = (fs::temp_directory_path() / ("morphe-ev-" + std::to_string(::getpid()))).string();
  fs::create_directories(dir);
  rt.set_evidence_dir(dir);
  rt.begin();

  KeyPair byz = kps[1];
  wire::Bytes p1 = make_prop(1, 0, byz, "value-AAAA");
  wire::Bytes p2 = make_prop(1, 0, byz, "value-BBBB");
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(p1.data(), p1.size()));
  BOOST_TEST(rt.evidence_count() == 0u);
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(p2.data(), p2.size()));
  BOOST_TEST(rt.evidence_count() == 1u);

  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(p1.data(), p1.size()));
  BOOST_TEST(rt.evidence_count() == 1u);

  KeyPair attacker = KeyPair::generate();
  wire::Bytes forged = make_prop_as(1, 0, byz.pub, attacker, "value-FORGED");
  rt.on_message(attacker.pub, services::MsgType::Prop, wire::View(forged.data(), forged.size()));
  BOOST_TEST(rt.evidence_count() == 1u);

  KeyPair outsider = KeyPair::generate();
  wire::Bytes o1 = make_prop(1, 0, outsider, "out-AAAA");
  wire::Bytes o2 = make_prop(1, 0, outsider, "out-BBBB");
  rt.on_message(outsider.pub, services::MsgType::Prop, wire::View(o1.data(), o1.size()));
  rt.on_message(outsider.pub, services::MsgType::Prop, wire::View(o2.data(), o2.size()));
  BOOST_TEST(rt.evidence_count() == 1u);

  wire::Bytes f1 = make_prop(100000, 0, byz, "far-AAAA");
  wire::Bytes f2 = make_prop(100000, 0, byz, "far-BBBB");
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(f1.data(), f1.size()));
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(f2.data(), f2.size()));
  BOOST_TEST(rt.evidence_count() == 1u);

  wire::Bytes truncated(4, 0x00);
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(truncated.data(), truncated.size()));

  bool found = false;
  for (const auto& e : fs::directory_iterator(dir)) {
    std::ifstream f(e.path());
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    if (s.find("double-sign") != std::string::npos && s.find("value_a") != std::string::npos &&
        s.find("value_b") != std::string::npos)
      found = true;
  }
  BOOST_TEST(found);
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(PropWithTrailingBytesRejected) {
  namespace fs = std::filesystem;
  auto kps = morphe::mesh_keys(2);
  services::Genesis g = morphe::mesh_genesis(kps);
  services::Runtime rt(g, kps[0]);
  const std::string dir = (fs::temp_directory_path() / ("morphe-f10-" + std::to_string(::getpid()))).string();
  fs::create_directories(dir);
  rt.set_evidence_dir(dir);
  rt.begin();
  KeyPair byz = kps[1];

  wire::Bytes p1 = make_prop(1, 0, byz, "value-AAAA");
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(p1.data(), p1.size()));
  BOOST_TEST(rt.evidence_count() == 0u);

  wire::Bytes p2_bad = make_prop(1, 0, byz, "value-BBBB");
  p2_bad.push_back(0xAB);
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(p2_bad.data(), p2_bad.size()));
  BOOST_TEST(rt.evidence_count() == 0u);

  wire::Bytes p2 = make_prop(1, 0, byz, "value-BBBB");
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(p2.data(), p2.size()));
  BOOST_TEST(rt.evidence_count() == 1u);
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(RpcErrorIsStdExceptionAndHandleThrowsOnlyRpcError) {
  try { throw morphe::RpcError{-32603, "boom"}; }
  catch (const std::exception& e) { BOOST_TEST(std::string(e.what()) == "boom"); }

  KeyPair a = KeyPair::generate();
  services::Genesis g; g.chain_id = "rpcerr"; g.validators = {a.pub};
  services::Runtime rt(g, a);
  morphe::RpcService svc(rt);

  bool threw = false;
  try { svc.handle("no.such.method", json::object{}); }
  catch (const morphe::RpcError& e) { threw = true; BOOST_TEST(e.code == -32601); }
  BOOST_TEST(threw);

  bool threw2 = false;
  try { svc.handle("query.balance", json::object{{"pubkey", 123}}); }
  catch (const morphe::RpcError&) { threw2 = true; }
  BOOST_TEST(threw2);
}

BOOST_AUTO_TEST_CASE(CrossChainReplayRejected) {
  namespace fs = std::filesystem;
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  auto mk = [&](const char* chain) {
    services::Genesis g;
    g.chain_id = chain;
    g.validators = {a.pub};
    g.allocations = {{a.pub, 1000}};
    return services::App::from_genesis(g);
  };
  services::App x = mk("chain-X"), y = mk("chain-Y");

  wire::Bytes to = rpc_acct_key(b.pub);
  services::TransferOp op = services::make_transfer(a, kv_view(to), 100, 0, sv(std::string("chain-X")));
  BOOST_TEST((x.admit_transfer(op) == services::Admit::Ok));
  BOOST_TEST((y.admit_transfer(op) == services::Admit::BadSig));

  auto kps = morphe::mesh_keys(2);
  services::Runtime rt(morphe::mesh_genesis(kps), kps[0]);
  const std::string dir = (fs::temp_directory_path() / ("morphe-b1-" + std::to_string(::getpid()))).string();
  fs::create_directories(dir);
  rt.set_evidence_dir(dir);
  rt.begin();
  KeyPair byz = kps[1];
  wire::Bytes w1 = make_prop_as(1, 0, byz.pub, byz, "v-AAAA", "wrong-chain");
  wire::Bytes w2 = make_prop_as(1, 0, byz.pub, byz, "v-BBBB", "wrong-chain");
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(w1.data(), w1.size()));
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(w2.data(), w2.size()));
  BOOST_TEST(rt.evidence_count() == 0u);
  wire::Bytes r1 = make_prop_as(1, 0, byz.pub, byz, "v-AAAA");
  wire::Bytes r2 = make_prop_as(1, 0, byz.pub, byz, "v-BBBB");
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(r1.data(), r1.size()));
  rt.on_message(byz.pub, services::MsgType::Prop, wire::View(r2.data(), r2.size()));
  BOOST_TEST(rt.evidence_count() == 1u);
  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(GracefulLeaveRemovesValidator) {
  morphe::MorpheMeshCluster c(5, life_g(5));
  BOOST_TEST(c.nodes[0]->member_count() == 5u);

  auto hook = [&](morphe::MorpheMeshCluster& cl, uint64_t iters) {
    if (cl.nodes[0]->applied_height() >= 2 && cl.nodes[0]->is_member(cl.kps[4].pub) &&
        (iters % 12 == 0)) {
      for (int i = 0; i < 5; i++)
        if (cl.active[i])
          cl.nodes[i]->submit_gov_vote(consensus::Governance::Kind::Remove, cl.kps[4].pub);
    }
  };
  BOOST_TEST(c.run(/*goal=*/20, /*needed=*/4, /*max_events=*/16000000, hook));
  BOOST_TEST(!c.nodes[0]->is_member(c.kps[4].pub));
  BOOST_TEST(c.nodes[0]->member_count() == 4u);
  BOOST_TEST(c.committed(20) >= 4);
}

BOOST_AUTO_TEST_CASE(FreshNodeJoinsAndCatchesUp) {
  morphe::MorpheMeshCluster c(4, life_g(4));
  const int joiner = 3;
  c.deactivate(joiner);
  bool joined = false;
  auto hook = [&](morphe::MorpheMeshCluster& cl, uint64_t) {
    uint64_t tip = 0;
    for (int i = 0; i < 4; i++)
      if (i != joiner && cl.nodes[i]->applied_height() > tip) tip = cl.nodes[i]->applied_height();
    if (!joined && tip >= 3) { cl.reactivate(joiner); joined = true; }
  };
  BOOST_TEST(c.run(/*goal=*/5, /*needed=*/4, /*max_events=*/8000000, hook));
  BOOST_TEST(joined);
  BOOST_TEST(c.nodes[joiner]->applied_height() >= 5u);
  BOOST_TEST(c.all_agree());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheRpc)

BOOST_AUTO_TEST_CASE(SubmitTxRejectsMultiOpBatch) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "rpc";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 1000}};
  services::Runtime rt(g, a);
  morphe::RpcService rpc(rt);
  wire::Bytes to = rpc_acct_key(KeyPair::generate().pub);
  services::TransferOp o1 = services::make_transfer(a, kv_view(to), 1, 0, sv(g.chain_id));
  services::TransferOp o2 = services::make_transfer(a, kv_view(to), 1, 1, sv(g.chain_id));
  services::Decoded batch;
  batch.transfers = {o1, o2};
  const wire::Bytes bb = services::encode_ops(batch);
  BOOST_CHECK_THROW(rpc.handle("submit_tx", json::object{{"tx", to_hex(bb.data(), bb.size())}}),
                    morphe::RpcError);
  json::value ok = rpc.handle("submit_tx", json::object{{"tx", tx_hex(o1)}});
  BOOST_TEST(ok.as_object().at("accepted").as_bool());
}

BOOST_AUTO_TEST_CASE(QueriesReflectState) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "rpc";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 500}};
  services::Runtime rt(g, a);
  morphe::RpcService rpc(rt);

  json::value bal = rpc.handle("query.balance", json::object{{"pubkey", to_hex(a.pub.data(), 32)}});
  BOOST_TEST(bal.as_object().at("balance").as_uint64() == 500u);

  json::value acc = rpc.handle("query.account", json::object{{"pubkey", to_hex(a.pub.data(), 32)}});
  BOOST_TEST(acc.as_object().at("exists").as_bool());
  BOOST_TEST(acc.as_object().at("sequence").as_uint64() == 0u);

  json::value vs = rpc.handle("query.validators", json::object{});
  BOOST_TEST(vs.as_object().at("count").as_uint64() == 1u);

  json::value st = rpc.handle("status", json::object{});
  BOOST_TEST(st.as_object().at("is_validator").as_bool());
  BOOST_TEST(st.as_object().contains("apphash"));

  BOOST_CHECK_THROW(rpc.handle("no.such.method", json::object{}), morphe::RpcError);
}

BOOST_AUTO_TEST_CASE(ControlMethodsOpenNoAuth) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "rpc";
  g.validators = {a.pub};
  services::Runtime rt(g, a);
  morphe::RpcService rpc(rt);

  KeyPair b = KeyPair::generate();
  json::value r = rpc.handle(
      "admin.gov_vote", json::object{{"kind", "add"}, {"target", to_hex(b.pub.data(), 32)}});
  BOOST_TEST(r.as_object().at("ok").as_bool());
  BOOST_TEST(r.as_object().at("kind").as_string() == "add");

  BOOST_CHECK_THROW(rpc.handle("no.such.method", json::object{}), morphe::RpcError);
}

BOOST_AUTO_TEST_CASE(AdminSnapshotRoundTrip) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "rpc";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 1000}};

  services::Runtime rtA(g, a);
  morphe::RpcService rpcA(rtA);
  rtA.run_to(1);
  const std::string hA = rpcA.handle("query.apphash", json::object{})
                             .as_object().at("apphash").as_string().c_str();
  const std::string path = "/tmp/morphe-rpc-snap-" + std::to_string(::getpid()) + ".snap";
  rpcA.handle("admin.snapshot_dump", json::object{{"token", "tok"}, {"path", path}});

  services::Runtime rtB(g, a);
  morphe::RpcService rpcB(rtB);
  const std::string hB0 = rpcB.handle("query.apphash", json::object{})
                              .as_object().at("apphash").as_string().c_str();
  BOOST_TEST(hB0 != hA);

  json::value load = rpcB.handle("admin.snapshot_load", json::object{{"token", "tok"}, {"path", path}});
  BOOST_TEST(load.as_object().at("ok").as_bool());
  const std::string hB1 = rpcB.handle("query.apphash", json::object{})
                              .as_object().at("apphash").as_string().c_str();
  BOOST_TEST(hB1 == hA);
  std::remove(path.c_str());
}

BOOST_AUTO_TEST_CASE(SubmitPollBalanceEndToEnd) {
  auto kps = morphe::mesh_keys(4);
  services::Genesis g = morphe::mesh_genesis(kps);
  g.allocations = {{kps[0].pub, 1000}};
  morphe::SimMesh mesh;
  mesh.init(g.validators);
  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<services::Runtime>> rts;
  for (int i = 0; i < 4; i++) ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 4; i++) rts.push_back(std::make_unique<services::Runtime>(g, kps[i], services::NodeOptions{0}, ports[i].get()));

  int commit_events = 0;
  rts[1]->app().add_on_commit([&](const services::CommitEvent& e) { if (e.height > 0) ++commit_events; });

  morphe::RpcService rpc0(*rts[0]);
  wire::Bytes to = rpc_acct_key(kps[1].pub);
  services::TransferOp op = services::make_transfer(kps[0], kv_view(to), 100, 0, sv(g.chain_id));
  json::value sub = rpc0.handle("submit_tx", json::object{{"tx", tx_hex(op)}});
  BOOST_TEST(sub.as_object().at("accepted").as_bool());
  const std::string txid = sub.as_object().at("tx_id").as_string().c_str();

  for (auto& rt : rts) rt->begin();
  bool reached = false;
  for (int iter = 0; iter < 200000 && !reached; ++iter) {
    bool progress = false;
    for (auto& rt : rts) if (rt->pump()) progress = true;
    for (auto& rt : rts) if (rt->advance()) progress = true;
    if (!progress) for (auto& rt : rts) rt->fire_one_timeout();
    reached = true;
    for (auto& rt : rts) if (rt->height() < 2) reached = false;
  }

  morphe::RpcService rpc2(*rts[2]);
  json::value res = rpc2.handle("query.tx", json::object{{"tx_id", txid}});
  BOOST_TEST(res.as_object().at("committed").as_bool());
  BOOST_TEST(res.as_object().at("applied").as_bool());

  for (int i = 0; i < 4; i++) {
    morphe::RpcService rpc(*rts[i]);
    json::value b = rpc.handle("query.balance", json::object{{"pubkey", to_hex(kps[1].pub.data(), 32)}});
    BOOST_TEST(b.as_object().at("balance").as_uint64() == 100u);
  }
  BOOST_TEST(commit_events > 0);
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheRpcServer)

namespace beast_t = boost::beast;
namespace http_t = boost::beast::http;
namespace ws_t = boost::beast::websocket;
namespace net_t = boost::asio;
using tcp_t = boost::asio::ip::tcp;

struct SoloDrive {
  net_t::io_context& io;
  services::Runtime& rt;
  net_t::steady_timer timer;
  bool begun = false;
  SoloDrive(net_t::io_context& io_, services::Runtime& rt_) : io(io_), rt(rt_), timer(io_) {}
  void tick() {
    if (!begun) { rt.begin(); begun = true; }
    uint64_t h0 = rt.height();
    rt.pump();
    rt.advance();
    if (rt.height() == h0) rt.fire_one_timeout();
    timer.expires_after(std::chrono::milliseconds(2));
    timer.async_wait([this](const boost::system::error_code& ec) { if (!ec) tick(); });
  }
};

static json::value http_rpc(uint16_t port, const std::string& method, json::object params) {
  net_t::io_context cio;
  tcp_t::socket sock(cio);
  sock.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
  json::object body{{"jsonrpc", "2.0"}, {"method", method}, {"params", params}, {"id", 1}};
  http_t::request<http_t::string_body> req(http_t::verb::post, "/", 11);
  req.set(http_t::field::host, "localhost");
  req.set(http_t::field::content_type, "application/json");
  req.body() = json::serialize(body);
  req.prepare_payload();
  http_t::write(sock, req);
  beast_t::flat_buffer b;
  http_t::response<http_t::string_body> res;
  http_t::read(sock, b, res);
  beast_t::error_code ec;
  sock.shutdown(tcp_t::socket::shutdown_both, ec);
  return json::parse(res.body());
}

static std::pair<int, std::string> http_get(uint16_t port, const std::string& target) {
  net_t::io_context cio;
  tcp_t::socket sock(cio);
  sock.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
  http_t::request<http_t::empty_body> req(http_t::verb::get, target, 11);
  req.set(http_t::field::host, "localhost");
  http_t::write(sock, req);
  beast_t::flat_buffer b;
  http_t::response<http_t::string_body> res;
  http_t::read(sock, b, res);
  beast_t::error_code ec;
  sock.shutdown(tcp_t::socket::shutdown_both, ec);
  return {static_cast<int>(res.result_int()), res.body()};
}

static std::pair<int, std::string> http_post(uint16_t port, const std::string& target,
                                             const std::string& body) {
  net_t::io_context cio;
  tcp_t::socket sock(cio);
  sock.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
  http_t::request<http_t::string_body> req(http_t::verb::post, target, 11);
  req.set(http_t::field::host, "localhost");
  req.body() = body;
  req.prepare_payload();
  http_t::write(sock, req);
  beast_t::flat_buffer b;
  http_t::response<http_t::string_body> res;
  http_t::read(sock, b, res);
  beast_t::error_code ec;
  sock.shutdown(tcp_t::socket::shutdown_both, ec);
  return {static_cast<int>(res.result_int()), res.body()};
}

BOOST_AUTO_TEST_CASE(HttpAndWebSocketEndToEnd) {
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "srv";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 1000}};
  net_t::io_context io;
  services::Runtime rt(g, a);
  morphe::RpcService svc(rt);
  morphe::RpcHttpServer server(io, svc, 0);
  server.start();
  server.attach_events();
  const uint16_t port = server.port();

  SoloDrive drive(io, rt);
  drive.tick();
  std::thread worker([&] { io.run(); });

  auto hexpk = [](const PubKey& k) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto c : k) { s.push_back(H[c >> 4]); s.push_back(H[c & 0x0f]); }
    return s;
  };

  try {
    std::vector<uint64_t> heights;
    {
      net_t::io_context wio;
      tcp_t::socket sock(wio);
      sock.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
      ws_t::stream<tcp_t::socket> ws(std::move(sock));
      ws.handshake("localhost", "/");
      ws.write(net_t::buffer(json::serialize(
          json::object{{"method", "subscribe"}, {"params", json::object{{"topic", "height"}}}})));
      beast_t::flat_buffer wb;
      ws.read(wb);
      wb.consume(wb.size());
      while (heights.size() < 3) {
        ws.read(wb);
        json::value v = json::parse(beast_t::buffers_to_string(wb.data()));
        wb.consume(wb.size());
        const json::object& o = v.as_object();
        if (o.contains("topic") && o.at("topic").as_string() == "height")
          heights.push_back(ju64(o.at("event").as_object().at("height")));
      }
      beast_t::error_code ec;
      ws.close(ws_t::close_code::normal, ec);
    }
    BOOST_TEST(heights.size() == 3u);
    BOOST_TEST(heights[1] > heights[0]);
    BOOST_TEST(heights[2] > heights[1]);

    json::value bal = http_rpc(port, "query.balance", json::object{{"pubkey", hexpk(a.pub)}});
    BOOST_TEST(ju64(bal.as_object().at("result").as_object().at("balance")) == 1000u);

    wire::Bytes to = rpc_acct_key(b.pub);
    services::TransferOp op = services::make_transfer(a, kv_view(to), 100, 0, sv(g.chain_id));
    json::value sub = http_rpc(port, "submit_tx", json::object{{"tx", tx_hex(op)}});
    BOOST_TEST(sub.as_object().at("result").as_object().at("accepted").as_bool());
    const std::string txid = sub.as_object().at("result").as_object().at("tx_id").as_string().c_str();

    bool committed = false;
    for (int i = 0; i < 500 && !committed; ++i) {
      json::value r = http_rpc(port, "query.tx", json::object{{"tx_id", txid}});
      committed = r.as_object().at("result").as_object().at("committed").as_bool();
      if (!committed) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    BOOST_TEST(committed);
    json::value b2 = http_rpc(port, "query.balance", json::object{{"pubkey", hexpk(b.pub)}});
    BOOST_TEST(ju64(b2.as_object().at("result").as_object().at("balance")) == 100u);

    json::value adm = http_rpc(port, "admin.set_log_level", json::object{{"level", "debug"}});
    BOOST_TEST(!adm.as_object().at("result").as_object().at("ok").as_bool());
    BOOST_TEST(adm.as_object().at("result").as_object().at("reason").as_string() == "not implemented");

    auto health = http_get(port, "/health");
    BOOST_TEST(health.first == 200);
    BOOST_TEST(health.second.find("\"ready\":true") != std::string::npos);
    auto metrics = http_get(port, "/metrics");
    BOOST_TEST(metrics.first == 200);
    BOOST_TEST(metrics.second.find("morphe_height") != std::string::npos);
    BOOST_TEST(metrics.second.find("morphe_mempool_size") != std::string::npos);
    BOOST_TEST(metrics.second.find("morphe_validators") != std::string::npos);
  } catch (...) {
    net_t::post(io, [&] { io.stop(); });
    worker.join();
    throw;
  }

  net_t::post(io, [&] { io.stop(); });
  worker.join();
}

BOOST_AUTO_TEST_CASE(PublishSurvivesSlowSubscriber) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "slowsub";
  g.validators = {a.pub};
  net_t::io_context io;
  services::Runtime rt(g, a);
  morphe::RpcService svc(rt);
  morphe::RpcHttpServer server(io, svc, 0);
  server.start();
  const uint16_t port = server.port();
  std::thread worker([&] { io.run(); });

  auto subscribe_height = [&](ws_t::stream<tcp_t::socket>& ws) {
    ws.write(net_t::buffer(json::serialize(
        json::object{{"method", "subscribe"}, {"params", json::object{{"topic", "height"}}}})));
    beast_t::flat_buffer ack;
    ws.read(ack);
  };

  net_t::io_context cio;
  try {
    tcp_t::socket ss(cio);
    ss.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
    ws_t::stream<tcp_t::socket> slow(std::move(ss));
    slow.handshake("localhost", "/");
    subscribe_height(slow);

    std::atomic<bool> done{false};
    for (int i = 0; i < 20000; ++i)
      net_t::post(io, [&server] { server.publish("height", json::object{{"height", 1}}); });
    net_t::post(io, [&done] { done = true; });
    for (int i = 0; i < 5000 && !done.load(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    BOOST_TEST(done.load());

    tcp_t::socket fs(cio);
    fs.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
    ws_t::stream<tcp_t::socket> fresh(std::move(fs));
    fresh.handshake("localhost", "/");
    subscribe_height(fresh);
    net_t::post(io, [&server] { server.publish("height", json::object{{"height", 7}}); });
    beast_t::flat_buffer fb;
    fresh.read(fb);
    json::value v = json::parse(beast_t::buffers_to_string(fb.data()));
    BOOST_TEST(v.as_object().at("topic").as_string() == "height");
    beast_t::error_code ec;
    fresh.close(ws_t::close_code::normal, ec);
    slow.close(ws_t::close_code::normal, ec);
  } catch (...) {
    net_t::post(io, [&] { io.stop(); });
    worker.join();
    throw;
  }
  net_t::post(io, [&] { io.stop(); });
  worker.join();
}

BOOST_AUTO_TEST_CASE(ClientRestRoundTrip) {
  KeyPair a = KeyPair::generate(), b = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "crest";
  g.validators = {a.pub};
  g.allocations = {{a.pub, 1000}};
  net_t::io_context io;
  services::Runtime rt(g, a);
  morphe::RpcService svc(rt);
  morphe::ClientRestServer client(io, svc, 0, "127.0.0.1");
  client.start();
  const uint16_t port = client.port();
  SoloDrive drive(io, rt);
  drive.tick();
  std::thread worker([&] { io.run(); });

  auto hexpk = [](const PubKey& k) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto c : k) { s.push_back(H[c >> 4]); s.push_back(H[c & 0x0f]); }
    return s;
  };
  try {
    auto h = http_get(port, "/height");
    BOOST_TEST(h.first == 200);
    BOOST_TEST(h.second.find("\"height\":") != std::string::npos);

    auto bal = http_get(port, "/balance/" + hexpk(a.pub));
    BOOST_TEST(bal.first == 200);
    BOOST_TEST(bal.second.find("\"balance\":1000") != std::string::npos);

    wire::Bytes to = rpc_acct_key(b.pub);
    services::TransferOp op = services::make_transfer(a, kv_view(to), 100, 0, sv(g.chain_id));
    auto sub = http_post(port, "/tx", tx_hex(op));
    BOOST_TEST(sub.first == 200);
    BOOST_TEST(sub.second.find("\"accepted\":true") != std::string::npos);

    bool committed = false;
    for (int i = 0; i < 500 && !committed; ++i) {
      auto b2 = http_get(port, "/balance/" + hexpk(b.pub));
      committed = b2.second.find("\"balance\":100") != std::string::npos;
      if (!committed) std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    BOOST_TEST(committed);

    auto bad = http_post(port, "/tx", "zznothex");
    BOOST_TEST(bad.first == 400);
    BOOST_TEST(bad.second.find("invalid hex") != std::string::npos);
    BOOST_TEST(bad.second.find("wire:") == std::string::npos);

    BOOST_TEST(http_get(port, "/status").first == 404);
    BOOST_TEST(http_get(port, "/validators").first == 404);
    BOOST_TEST(http_get(port, "/apphash").first == 404);
    BOOST_TEST(http_get(port, "/gov_vote").first == 404);
    BOOST_TEST(http_get(port, "/no/such/thing").first == 404);
  } catch (...) {
    net_t::post(io, [&] { io.stop(); });
    worker.join();
    throw;
  }
  net_t::post(io, [&] { io.stop(); });
  worker.join();
}

BOOST_AUTO_TEST_CASE(ClientRestDropsSlowLoris) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "crestidle";
  g.validators = {a.pub};
  net_t::io_context io;
  services::Runtime rt(g, a);
  morphe::RpcService svc(rt);
  morphe::ClientRestServer client(io, svc, 0, "127.0.0.1", std::chrono::milliseconds(200));
  client.start();
  const uint16_t port = client.port();
  std::thread worker([&] { io.run(); });

  try {
    net_t::io_context cio;
    tcp_t::socket sock(cio);
    sock.connect(tcp_t::endpoint(net_t::ip::make_address("127.0.0.1"), port));
    beast_t::error_code ec;
    std::array<uint8_t, 1> buf{};
    net_t::read(sock, net_t::buffer(buf), ec);
    BOOST_TEST(!!ec);
  } catch (...) {
    net_t::post(io, [&] { io.stop(); });
    worker.join();
    throw;
  }
  net_t::post(io, [&] { io.stop(); });
  worker.join();
}

BOOST_AUTO_TEST_CASE(AdminShutdownHaltsTheLoop) {
  KeyPair a = KeyPair::generate();
  services::Genesis g;
  g.chain_id = "sd";
  g.validators = {a.pub};
  net_t::io_context io;
  services::Runtime rt(g, a);
  morphe::RpcService svc(rt);
  rt.set_shutdown_hook([&io] { net_t::post(io, [&io] { io.stop(); }); });

  SoloDrive drive(io, rt);
  drive.tick();
  net_t::post(io, [&] {
    if (rt.height() >= 2) { svc.handle("admin.shutdown", json::object{}); }
    else { net_t::post(io, [&] { svc.handle("admin.shutdown", json::object{}); }); }
  });
  io.run();
  BOOST_TEST(io.stopped());
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheAsioMesh)

static uint32_t asio_tag() {
  const char* c = "morphe-asio";
  return morphe::chain_tag_of(wire::View(reinterpret_cast<const uint8_t*>(c), std::strlen(c)));
}

template <class Pred>
static bool pump_until(boost::asio::io_context& io, Pred pred) {
  for (int i = 0; i < 5000000; ++i) {
    if (pred()) return true;
    io.poll();
    if (io.stopped()) io.restart();
  }
  return pred();
}

BOOST_AUTO_TEST_CASE(DirectDeliveryOverTcp) {
  auto kps = morphe::mesh_keys(2);
  boost::asio::io_context io;
  const uint32_t tag = asio_tag();
  morphe::AsioMesh a(io, kps[0], tag, 0);
  morphe::AsioMesh b(io, kps[1], tag, 0);
  a.add_peer(kps[1].pub, "127.0.0.1", b.port());
  b.add_peer(kps[0].pub, "127.0.0.1", a.port());

  bool got = false;
  PubKey gsrc{};
  std::string gpayload;
  b.on_recv = [&](const PubKey& src, services::MsgType type, wire::View pl) {
    if (type != services::MsgType::Consensus) return;
    got = true;
    gsrc = src;
    gpayload.assign(pl.begin(), pl.end());
  };
  a.start();
  b.start();

  BOOST_TEST(pump_until(io, [&] { return a.connected() >= 1 && b.connected() >= 1; }));
  const char* msg = "hello-mesh";
  a.broadcast(services::MsgType::Consensus, services::Channel::Consensus,
              wire::View(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg)));
  BOOST_TEST(pump_until(io, [&] { return got; }));
  BOOST_TEST(got);
  BOOST_TEST((gsrc == kps[0].pub));
  BOOST_TEST(gpayload == "hello-mesh");
}

BOOST_AUTO_TEST_CASE(RelayedDeliveryTwoHop) {
  auto kps = morphe::mesh_keys(3);
  boost::asio::io_context io;
  const uint32_t tag = asio_tag();
  morphe::AsioMesh a(io, kps[0], tag, 0);
  morphe::AsioMesh b(io, kps[1], tag, 0);
  morphe::AsioMesh c(io, kps[2], tag, 0);
  a.add_peer(kps[1].pub, "127.0.0.1", b.port());
  b.add_peer(kps[0].pub, "127.0.0.1", a.port());
  b.add_peer(kps[2].pub, "127.0.0.1", c.port());
  c.add_peer(kps[1].pub, "127.0.0.1", b.port());

  bool got = false;
  PubKey gsrc{};
  c.on_recv = [&](const PubKey& src, services::MsgType type, wire::View) {
    if (type != services::MsgType::Consensus) return;
    got = true;
    gsrc = src;
  };
  a.start();
  b.start();
  c.start();

  BOOST_TEST(pump_until(io, [&] {
    return a.connected() >= 1 && c.connected() >= 1 && b.connected() >= 2;
  }));
  const char* msg = "via-relay";
  a.send(kps[2].pub, services::MsgType::Consensus, services::Channel::Consensus,
         wire::View(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg)));
  BOOST_TEST(pump_until(io, [&] { return got; }));
  BOOST_TEST(got);
  BOOST_TEST((gsrc == kps[0].pub));
}

BOOST_AUTO_TEST_CASE(HandshakeAuthenticatesMembersRejectsImposters) {
  using tcp = boost::asio::ip::tcp;
  auto kps = morphe::mesh_keys(3);
  boost::asio::io_context io;
  const uint32_t tag = asio_tag();
  morphe::AsioMesh a(io, kps[0], tag, 0);
  morphe::AsioMesh b(io, kps[1], tag, 0);
  a.add_peer(kps[1].pub, "127.0.0.1", b.port());
  b.add_peer(kps[0].pub, "127.0.0.1", a.port());
  a.start();
  auto pump_n = [&](int n) { for (int i = 0; i < n; ++i) { io.poll(); if (io.stopped()) io.restart(); } };

  auto impostor = std::make_shared<tcp::socket>(io);
  impostor->connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), a.port()));
  pump_n(50000);
  std::vector<uint8_t> hdr(morphe::FRAME_HEADER_SIZE);
  boost::asio::read(*impostor, boost::asio::buffer(hdr.data(), hdr.size()));
  const uint8_t* lp = hdr.data() + morphe::FRAME_HEADER_SIZE - 4;
  uint32_t plen = (uint32_t(lp[0]) << 24) | (uint32_t(lp[1]) << 16) | (uint32_t(lp[2]) << 8) | lp[3];
  std::vector<uint8_t> full(morphe::FRAME_HEADER_SIZE + plen);
  std::copy(hdr.begin(), hdr.end(), full.begin());
  boost::asio::read(*impostor, boost::asio::buffer(full.data() + morphe::FRAME_HEADER_SIZE, plen));
  morphe::FrameHeader ah;
  wire::View a_challenge = morphe::decode_frame(wire::View(full.data(), full.size()), ah);
  {  // HelloAuth: sign (tag || kps[1] || a_challenge) with kps[2]'s key: bad PoP for kps[1]
    wire::Bytes sb;
    wire::Writer sw(sb);
    sw.raw(wire::View(reinterpret_cast<const uint8_t*>("MORPHE_HELLO_V1"), 15));
    sw.u32(tag);
    sw.raw(wire::View(kps[1].pub.data(), 32));
    sw.raw(a_challenge);
    Sig bad = kps[2].sign(wire::View(sb.data(), sb.size()));
    morphe::FrameHeader h;
    h.chain_tag = tag; h.type = services::MsgType::HelloAuth; h.src = kps[1].pub; h.dest = kps[0].pub;
    h.msg_id = morphe::make_msg_id(kps[1].pub, kps[0].pub, wire::View(bad.data(), 64));
    wire::Bytes f = morphe::encode_frame(h, wire::View(bad.data(), 64));
    boost::asio::write(*impostor, boost::asio::buffer(f));
  }
  pump_n(100000);
  BOOST_TEST(a.connected() == 0u);

  b.start();
  BOOST_TEST(pump_until(io, [&] { return a.connected() >= 1 && b.connected() >= 1; }));
  pump_n(100000);
  BOOST_TEST(a.connected() == 1u);
  BOOST_TEST((b.connected() == 1u));
}

BOOST_AUTO_TEST_CASE(HandshakeDeadlineDropsUnauthenticatedSocket) {
  using tcp = boost::asio::ip::tcp;
  auto kps = morphe::mesh_keys(1);
  boost::asio::io_context io;
  const uint32_t tag = asio_tag();
  morphe::AsioMesh a(io, kps[0], tag, 0, std::chrono::milliseconds(150));
  a.start();

  tcp::socket loris(io);
  loris.connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), a.port()));
  io.run_for(std::chrono::milliseconds(60));

  std::vector<uint8_t> hdr(morphe::FRAME_HEADER_SIZE);
  boost::system::error_code rec;
  boost::asio::read(loris, boost::asio::buffer(hdr.data(), hdr.size()), rec);
  BOOST_TEST(!rec);
  const uint8_t* lp = hdr.data() + morphe::FRAME_HEADER_SIZE - 4;
  uint32_t plen = (uint32_t(lp[0]) << 24) | (uint32_t(lp[1]) << 16) | (uint32_t(lp[2]) << 8) | lp[3];
  std::vector<uint8_t> pl(plen);
  boost::asio::read(loris, boost::asio::buffer(pl.data(), plen), rec);
  BOOST_TEST(!rec);
  BOOST_TEST(a.connected() == 0u);

  io.run_for(std::chrono::milliseconds(400));
  uint8_t byte = 0;
  boost::system::error_code ec2;
  boost::asio::read(loris, boost::asio::buffer(&byte, 1), ec2);
  BOOST_TEST(!!ec2);
  BOOST_TEST(a.connected() == 0u);
}

BOOST_AUTO_TEST_CASE(FourRuntimesCommitOverTcp) {
  auto kps = morphe::mesh_keys(4);
  services::Genesis g = morphe::mesh_genesis(kps);
  boost::asio::io_context io;
  const uint32_t tag =
      morphe::chain_tag_of(wire::View(reinterpret_cast<const uint8_t*>(g.chain_id.data()),
                                      g.chain_id.size()));

  std::vector<std::unique_ptr<morphe::AsioMesh>> meshes;
  for (int i = 0; i < 4; i++)
    meshes.push_back(std::make_unique<morphe::AsioMesh>(io, kps[i], tag, 0));
  for (int i = 0; i < 4; i++)
    for (int j = 0; j < 4; j++)
      if (i != j) meshes[i]->add_peer(kps[j].pub, "127.0.0.1", meshes[j]->port());

  std::vector<std::unique_ptr<services::Runtime>> rts;
  for (int i = 0; i < 4; i++)
    rts.push_back(std::make_unique<services::Runtime>(g, kps[i], services::NodeOptions{/*pace=*/0}, meshes[i].get()));

  for (auto& m : meshes) m->start();
  BOOST_TEST(pump_until(io, [&] {
    for (auto& m : meshes) if (m->connected() < 3) return false;
    return true;
  }));

  for (auto& rt : rts) rt->begin();
  const uint64_t GOAL = 2;
  int idle = 0;
  bool done = false;
  for (long it = 0; it < 50000000 && !done; ++it) {
    std::size_t n = io.poll();
    if (io.stopped()) io.restart();
    bool prog = false;
    for (auto& rt : rts) if (rt->pump()) prog = true;
    for (auto& rt : rts) if (rt->advance()) prog = true;
    done = true;
    for (auto& rt : rts) if (rt->height() < GOAL) done = false;
    if (n == 0 && !prog) { if (++idle > 50000) { for (auto& rt : rts) rt->fire_one_timeout(); idle = 0; } }
    else idle = 0;
  }

  for (auto& rt : rts) BOOST_TEST(rt->height() >= GOAL);
  Hash ref = rts[0]->node().composite_hash();
  for (auto& rt : rts)
    BOOST_TEST((rt->node().composite_hash() == ref));
}

BOOST_AUTO_TEST_SUITE_END()

BOOST_AUTO_TEST_SUITE(MorpheTestnet)

BOOST_AUTO_TEST_CASE(GeneratesConsistentHomes) {
  namespace fs = std::filesystem;
  const std::string dir =
      (fs::temp_directory_path() / ("morphe-tn-" + std::to_string(::getpid()))).string();
  fs::remove_all(dir);
  const int N = 4;
  const uint16_t base = 45000;

  services::Genesis g = morphe::generate_testnet(dir, N, base);
  const Hash want_hash = g.hash();

  std::vector<PubKey> keys;
  for (int i = 0; i < N; ++i) {
    const std::string home = dir + "/node" + std::to_string(i);
    BOOST_TEST(fs::exists(home + "/node.key"));
    BOOST_TEST(fs::exists(home + "/genesis.txt"));
    BOOST_TEST(fs::exists(home + "/config.txt"));
    BOOST_TEST(fs::exists(home + "/peers.txt"));

    std::ifstream gf(home + "/genesis.txt");
    std::ostringstream gs;
    gs << gf.rdbuf();
    services::Genesis gi = services::Genesis::parse(gs.str());
    BOOST_TEST((gi.hash() == want_hash));

    BOOST_TEST(morphe::read_config_u64(home, "listen_port", 0) == static_cast<uint64_t>(base + i));
    auto peers = morphe::parse_peers(home);
    BOOST_TEST(peers.size() == static_cast<size_t>(N - 1));
    for (const auto& p : peers) BOOST_TEST(p.host == "127.0.0.1");
    keys.push_back(services::load_key(home + "/node.key").pub);
  }

  for (int i = 0; i < N; ++i)
    for (int j = i + 1; j < N; ++j)
      BOOST_TEST((keys[i] != keys[j]));
  for (int i = 0; i < N; ++i)
    BOOST_TEST((keys[i] == g.validators[i]));

  auto peers0 = morphe::parse_peers(dir + "/node0");
  for (const auto& p : peers0) {
    BOOST_TEST((p.pk != keys[0]));
    bool is_member = false;
    for (const auto& v : g.validators) if (p.pk == v) is_member = true;
    BOOST_TEST(is_member);
  }

  fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(ParsePeersRejectsMalformedAndPortOverflow) {
  namespace fs = std::filesystem;
  const std::string home = (fs::temp_directory_path() / ("morphe-peers-" + std::to_string(::getpid()))).string();
  fs::create_directories(home);
  KeyPair a = KeyPair::generate();
  const std::string pk = services::pubkey_hex(a.pub);
  auto write = [&](const std::string& body) { std::ofstream f(home + "/peers.txt", std::ios::trunc); f << body; };

  write(pk + " 127.0.0.1 40000\n");
  BOOST_TEST(morphe::parse_peers(home).size() == 1u);
  write(pk + " 127.0.0.1 40000\n" + pk + "\n");
  BOOST_CHECK_THROW(morphe::parse_peers(home), std::runtime_error);
  write(pk + " 127.0.0.1 40000 extra\n");
  BOOST_CHECK_THROW(morphe::parse_peers(home), std::runtime_error);
  write("# a comment\n\n" + pk + " host 40000\n");
  BOOST_TEST(morphe::parse_peers(home).size() == 1u);
  fs::remove_all(home);

  BOOST_CHECK_THROW(morphe::generate_testnet(home, 4, 64000), std::runtime_error);
  fs::remove_all(home);
}

BOOST_AUTO_TEST_SUITE_END()
