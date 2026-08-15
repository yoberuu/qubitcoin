// Copyright (c) 2012-2022 Yelpful Technologies
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/dilithium.h>
#include <key.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sanity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(basic_sanity)
{
  BOOST_CHECK_MESSAGE(ECC_InitSanityCheck() == true, "secp256k1 sanity test");
  // QubitCoin: ML-DSA-65 is the chain's only signature scheme, and this also
  // pins the seeded-keygen mapping that wallet recovery depends on.
  BOOST_CHECK_MESSAGE(dilithium::SelfTest() == true, "ML-DSA-65 sanity test");
}

BOOST_AUTO_TEST_SUITE_END()
