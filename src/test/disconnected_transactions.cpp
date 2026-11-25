// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <boost/test/unit_test.hpp>
#include <core_memusage.h>
#include <kernel/disconnected_transactions.h>
#include <test/util/setup_common.h>

BOOST_FIXTURE_TEST_SUITE(disconnected_transactions, TestChain100Setup)

//! Tests that DisconnectedBlockTransactions limits its own memory properly
BOOST_AUTO_TEST_CASE(disconnectpool_memory_limits)
{
    // Use the coinbase transactions from TestChain100Setup. It doesn't matter whether these
    // transactions would realistically be in a block together, they just need distinct txids and
    // uniform size for this test to work.
    std::vector<CTransactionRef> block_vtx(m_coinbase_txns);
    BOOST_CHECK_EQUAL(block_vtx.size(), 100);

    // Roughly estimate sizes to sanity check that DisconnectedBlockTransactions::DynamicMemoryUsage
    // is within an expected range.

    // Overhead for the hashmap depends on number of buckets
    std::unordered_map<Txid, CTransaction*, SaltedTxidHasher> temp_map;
    temp_map.reserve(1);
    const size_t MAP_1{memusage::DynamicUsage(temp_map)};
    temp_map.reserve(100);
    const size_t MAP_100{memusage::DynamicUsage(temp_map)};

    const size_t TX_USAGE{RecursiveDynamicUsage(block_vtx.front())};
    for (const auto& tx : block_vtx)
        BOOST_CHECK_EQUAL(RecursiveDynamicUsage(tx), TX_USAGE);

    // Our overall formula is unordered map overhead + usage per entry.
    // Implementations may vary, but we're trying to guess the usage of data structures.
    const size_t ENTRY_USAGE_ESTIMATE{
        TX_USAGE
        // list entry: 2 pointers (next pointer and prev pointer) + element itself
        + memusage::MallocUsage((2 * sizeof(void*)) + sizeof(decltype(block_vtx)::value_type))
        // unordered map: 1 pointer for the hashtable + key and value
        + memusage::MallocUsage(sizeof(void*) + sizeof(decltype(temp_map)::key_type)
                                + sizeof(decltype(temp_map)::value_type))};

    // DisconnectedBlockTransactions that's just big enough for 1 transaction.
    {
        DisconnectedBlockTransactions disconnectpool{MAP_1 + ENTRY_USAGE_ESTIMATE};
        // Add just 2 (and not all 100) transactions to keep the unordered map's hashtable overhead
        // to a minimum and avoid all (instead of all but 1) transactions getting evicted.
        std::vector<CTransactionRef> two_txns({block_vtx.at(0), block_vtx.at(1)});
        auto evicted_txns{disconnectpool.AddTransactionsFromBlock(two_txns)};
        BOOST_CHECK(disconnectpool.DynamicMemoryUsage() <= MAP_1 + ENTRY_USAGE_ESTIMATE);

        // Only 1 transaction can be kept
        BOOST_CHECK_EQUAL(1, evicted_txns.size());
        // Transactions are added from back to front and eviction is FIFO.
        BOOST_CHECK_EQUAL(block_vtx.at(1), evicted_txns.front());

        disconnectpool.clear();
    }

    // DisconnectedBlockTransactions with a comfortable maximum memory usage so that nothing is evicted.
    // Record usage so we can check size limiting in the next test.
    size_t usage_full{0};
    {
        const size_t USAGE_100_OVERESTIMATE{MAP_100 + ENTRY_USAGE_ESTIMATE * 100};
        DisconnectedBlockTransactions disconnectpool{USAGE_100_OVERESTIMATE};
        auto evicted_txns{disconnectpool.AddTransactionsFromBlock(block_vtx)};
        BOOST_CHECK_EQUAL(evicted_txns.size(), 0);
        BOOST_CHECK(disconnectpool.DynamicMemoryUsage() <= USAGE_100_OVERESTIMATE);

        usage_full = disconnectpool.DynamicMemoryUsage();

        disconnectpool.clear();
    }

    // DisconnectedBlockTransactions that's just a little too small for all of the transactions.
    {
        const size_t MAX_MEMUSAGE_99{usage_full - sizeof(void*)};
        DisconnectedBlockTransactions disconnectpool{MAX_MEMUSAGE_99};
        auto evicted_txns{disconnectpool.AddTransactionsFromBlock(block_vtx)};
        BOOST_CHECK(disconnectpool.DynamicMemoryUsage() <= MAX_MEMUSAGE_99);

        // Only 1 transaction needed to be evicted
        BOOST_CHECK_EQUAL(1, evicted_txns.size());

        // Transactions are added from back to front and eviction is FIFO.
        // The last transaction of block_vtx should be the first to be evicted.
        BOOST_CHECK_EQUAL(block_vtx.back(), evicted_txns.front());

        disconnectpool.clear();
    }
}

BOOST_AUTO_TEST_CASE(disconnectpool_empty_population_and_reuse)
{
    DisconnectedBlockTransactions pool{MAX_DISCONNECTED_TX_POOL_BYTES};
#if defined(__APPLE__) && defined(__x86_64__)
    const auto empty_usage{pool.DynamicMemoryUsage()};
#endif
    const std::vector<CTransactionRef> empty;
    for (unsigned i = 0; i < 3; ++i) {
        BOOST_CHECK(pool.AddTransactionsFromBlock(empty).empty());
        pool.removeForBlock(empty);
        pool.clear();
        BOOST_CHECK(pool.take().empty());
#if defined(__APPLE__) && defined(__x86_64__)
        BOOST_CHECK_EQUAL(pool.DynamicMemoryUsage(), empty_usage);
#endif
    }

    for (unsigned cycle = 0; cycle < 3; ++cycle) {
        const std::vector<CTransactionRef> disconnected{
            m_coinbase_txns.at(0), m_coinbase_txns.at(1), m_coinbase_txns.at(2), m_coinbase_txns.at(3)};
        BOOST_CHECK(pool.AddTransactionsFromBlock(disconnected).empty());
        BOOST_CHECK_EQUAL(pool.size(), 4U);
        BOOST_CHECK(pool.AddTransactionsFromBlock(empty).empty());
        pool.removeForBlock({m_coinbase_txns.at(0), m_coinbase_txns.at(2)});
        BOOST_CHECK_EQUAL(pool.size(), 2U);
        const auto remaining{pool.take()};
        const std::vector<CTransactionRef> expected{m_coinbase_txns.at(3), m_coinbase_txns.at(1)};
        BOOST_CHECK_EQUAL_COLLECTIONS(remaining.begin(), remaining.end(), expected.begin(), expected.end());
        BOOST_CHECK_EQUAL(pool.size(), 0U);
        BOOST_CHECK(pool.AddTransactionsFromBlock({m_coinbase_txns.at(4), m_coinbase_txns.at(5)}).empty());
        pool.clear();
        BOOST_CHECK(pool.take().empty());
        BOOST_CHECK(pool.DynamicMemoryUsage() <= MAX_DISCONNECTED_TX_POOL_BYTES);
    }

    DisconnectedBlockTransactions zero_limit{0};
    const auto evicted{zero_limit.AddTransactionsFromBlock({m_coinbase_txns.at(6)})};
    BOOST_REQUIRE_EQUAL(evicted.size(), 1U);
    BOOST_CHECK(evicted.front() == m_coinbase_txns.at(6));
    BOOST_CHECK(zero_limit.take().empty());
}

BOOST_AUTO_TEST_SUITE_END()
