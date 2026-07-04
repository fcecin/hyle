
#include <boost/test/unit_test.hpp>

#include <hyle/services/kv/pow.h>
#include <hyle/services/ops.h>
#include <hyle/services/runtime.h>
#include <hyle/services/schema.h>

using namespace hyle;

namespace {
wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
}  // namespace

BOOST_AUTO_TEST_SUITE(ServicesEmbed)

BOOST_AUTO_TEST_CASE(CoreAndServicesAloneRunASoloEconomyNode) {
  KeyPair v = KeyPair::generate();
  morphe::Genesis g;
  g.chain_id = "embed";
  g.validators = {v.pub};
  g.allocations = {{v.pub, 1000}};
  morphe::Runtime rt(g, v, /*block_pace_ms=*/0);

  rt.run_to(3);
  BOOST_TEST(rt.height() >= 3u);

  KeyPair a = KeyPair::generate();
  Sha256PowVerifier pv;
  rt.app().submit_mint(morphe::make_mint(pv, rt.app().mint_key(), a, 4, 0, sv(g.chain_id)));
  rt.run_to(rt.height() + 3);
  const uint64_t after_mint = rt.app().balance(a.pub);
  BOOST_TEST(after_mint > 0u);

  wire::Bytes to;
  to.push_back(morphe::ACCOUNT_PREFIX);
  to.insert(to.end(), a.pub.begin(), a.pub.end());
  morphe::TransferOp op =
      morphe::make_transfer(v, wire::View(to.data(), to.size()), 50, 0, sv(g.chain_id));
  BOOST_TEST((rt.submit(op) == morphe::Admit::Ok));
  rt.run_to(rt.height() + 3);
  BOOST_TEST(rt.app().balance(a.pub) == after_mint + 50u);
}

BOOST_AUTO_TEST_SUITE_END()
