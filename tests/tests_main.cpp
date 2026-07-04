#define BOOST_TEST_MODULE HyleTests
#include <boost/test/included/unit_test.hpp>

#include <hyle/core/blog.h>

namespace {

struct BlogFixture {
  BlogFixture() {
    const blog::severity_level lvl = blog::debug;
    blog::init();
    blog::set_level(lvl);
    blog::set_level("hyle.node", lvl);
    blog::set_level("hyle.gov", lvl);
    blog::set_level("hyle.ledger", lvl);
  }
};

} // namespace

BOOST_TEST_GLOBAL_FIXTURE(BlogFixture);
