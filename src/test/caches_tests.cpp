// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#include <common/args.h>
#include <node/caches.h>
#include <util/byte_units.h>

#include <boost/test/unit_test.hpp>

#include <string>

using namespace node;

BOOST_AUTO_TEST_SUITE(caches_tests)

BOOST_AUTO_TEST_CASE(oversized_dbcache_warning)
{
    // memory restricted setup - cap is DEFAULT_DB_CACHE (450 MiB)
    BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/4_MiB, /*total_ram=*/1024_MiB));    // Under cap
    BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/512_MiB, /*total_ram=*/1024_MiB));  // At cap
    BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/1500_MiB, /*total_ram=*/1024_MiB)); // Over cap

    // 2 GiB RAM - cap is 75%
    BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/1500_MiB, /*total_ram=*/2048_MiB)); // Under cap
    BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/1600_MiB, /*total_ram=*/2048_MiB)); // Over cap

    if constexpr (SIZE_MAX == UINT64_MAX) {
        // 4 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/2500_MiB, /*total_ram=*/4096_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/3500_MiB, /*total_ram=*/4096_MiB)); // Over cap

        // 8 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/6000_MiB, /*total_ram=*/8192_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/7000_MiB, /*total_ram=*/8192_MiB)); // Over cap

        // 16 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/10'000_MiB, /*total_ram=*/16384_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/15'000_MiB, /*total_ram=*/16384_MiB)); // Over cap

        // 32 GiB RAM - cap is 75%
        BOOST_CHECK(!ShouldWarnOversizedDbCache(/*dbcache=*/20'000_MiB, /*total_ram=*/32768_MiB)); // Under cap
        BOOST_CHECK( ShouldWarnOversizedDbCache(/*dbcache=*/30'000_MiB, /*total_ram=*/32768_MiB)); // Over cap
    }
}

BOOST_AUTO_TEST_CASE(block_tree_cache_budget)
{
    ArgsManager args;
    args.ForceSetArg("-txindex", "0");
    args.ForceSetArg("-txospenderindex", "0");

#if (defined(_WIN32) && (defined(__x86_64__) || defined(_M_X64))) || (defined(__APPLE__) && defined(__aarch64__))
    constexpr auto large_block_tree_cache{64_MiB};
#else
    constexpr auto large_block_tree_cache{2_MiB};
#endif

    const auto check = [&](size_t budget_mib, size_t expected_block_tree_cache) {
        BOOST_TEST_CONTEXT("dbcache=" << budget_mib) {
            args.ForceSetArg("-dbcache", std::to_string(budget_mib));
            const auto sizes{CalculateCacheSizes(args)};
            BOOST_CHECK_EQUAL(sizes.kernel.block_tree_db, expected_block_tree_cache);
            BOOST_CHECK_EQUAL(sizes.kernel.coins_db, 8_MiB);
            BOOST_CHECK_EQUAL(sizes.index.tx_index + sizes.kernel.block_tree_db + sizes.kernel.coins_db + sizes.kernel.coins,
                              budget_mib * 1_MiB);
        }
    };

    check(511, 2_MiB);
    check(512, large_block_tree_cache);
    check(1024, large_block_tree_cache);

    args.ForceSetArg("-txindex", "1");
    check(512, 2_MiB);  // Txindex leaves less than 512 MiB for the kernel.
    check(1024, large_block_tree_cache);
}

BOOST_AUTO_TEST_SUITE_END()
