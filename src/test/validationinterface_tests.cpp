// Copyright (c) 2020-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>
#include <consensus/validation.h>
#include <kernel/mempool_entry.h>
#include <primitives/block.h>
#include <scheduler.h>
#include <test/util/setup_common.h>
#include <test/util/txmempool.h>
#include <util/check.h>
#include <validationinterface.h>

#include <atomic>
#include <memory>

BOOST_FIXTURE_TEST_SUITE(validationinterface_tests, ChainTestingSetup)

struct TestSubscriberNoop final : public CValidationInterface {
    void BlockChecked(const std::shared_ptr<const CBlock>&, const BlockValidationState&) override {}
};

BOOST_AUTO_TEST_CASE(unregister_validation_interface_race)
{
    std::atomic<bool> generate{true};

    // Start thread to generate notifications
    std::thread gen{[&] {
        BlockValidationState state_dummy;
        while (generate) {
            m_node.validation_signals->BlockChecked(std::make_shared<const CBlock>(), state_dummy);
        }
    }};

    // Start thread to consume notifications
    std::thread sub{[&] {
        // keep going for about 1 sec, which is 250k iterations
        for (int i = 0; i < 250000; i++) {
            auto sub = std::make_shared<TestSubscriberNoop>();
            m_node.validation_signals->RegisterSharedValidationInterface(sub);
            m_node.validation_signals->UnregisterSharedValidationInterface(sub);
        }
        // tell the other thread we are done
        generate = false;
    }};

    gen.join();
    sub.join();
    BOOST_CHECK(!generate);
}

class TestInterface : public CValidationInterface
{
public:
    TestInterface(ValidationSignals& signals, std::function<void()> on_call = nullptr, std::function<void()> on_destroy = nullptr)
        : m_on_call(std::move(on_call)), m_on_destroy(std::move(on_destroy)), m_signals{signals}
    {
    }
    virtual ~TestInterface()
    {
        if (m_on_destroy) m_on_destroy();
    }
    void BlockChecked(const std::shared_ptr<const CBlock>& block, const BlockValidationState& state) override
    {
        if (m_on_call) m_on_call();
    }
    void Call()
    {
        BlockValidationState state;
        m_signals.BlockChecked(std::make_shared<const CBlock>(), state);
    }
    std::function<void()> m_on_call;
    std::function<void()> m_on_destroy;
    ValidationSignals& m_signals;
};

// Regression test to ensure UnregisterAllValidationInterfaces calls don't
// destroy a validation interface while it is being called. Bug:
// https://github.com/bitcoin/bitcoin/pull/18551
BOOST_AUTO_TEST_CASE(unregister_all_during_call)
{
    bool destroyed = false;
    auto shared{std::make_shared<TestInterface>(
        *m_node.validation_signals,
        [&] {
            // First call should decrements reference count 2 -> 1
            m_node.validation_signals->UnregisterAllValidationInterfaces();
            BOOST_CHECK(!destroyed);
            // Second call should not decrement reference count 1 -> 0
            m_node.validation_signals->UnregisterAllValidationInterfaces();
            BOOST_CHECK(!destroyed);
        },
        [&] { destroyed = true; })};
    m_node.validation_signals->RegisterSharedValidationInterface(shared);
    BOOST_CHECK(shared.use_count() == 2);
    shared->Call();
    BOOST_CHECK(shared.use_count() == 1);
    BOOST_CHECK(!destroyed);
    shared.reset();
    BOOST_CHECK(destroyed);
}

BOOST_AUTO_TEST_CASE(queued_empty_removals_preserve_fifo_and_registration)
{
    struct Subscriber final : CValidationInterface {
        std::vector<std::pair<unsigned, std::vector<Txid>>> received;
        void MempoolTransactionsRemovedForBlock(const std::vector<RemovedMempoolTransactionInfo>& removed, unsigned height) override
        {
            std::vector<Txid> txids;
            for (const auto& tx : removed) txids.push_back(tx.info.m_tx->GetHash());
            received.emplace_back(height, std::move(txids));
        }
    };
    CScheduler scheduler;
    ValidationSignals signals{std::make_unique<SerialTaskRunner>(scheduler)};
    auto early{std::make_shared<Subscriber>()};
    auto late{std::make_shared<Subscriber>()};
    signals.RegisterSharedValidationInterface(early);
    for (unsigned height{1}; height <= 16; ++height) {
        signals.MempoolTransactionsRemovedForBlock({}, height);
    }
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vout.resize(1);
    const auto ref{MakeTransactionRef(tx)};
    TestMemPoolEntryHelper entry;
    std::vector<RemovedMempoolTransactionInfo> removed;
    removed.emplace_back(entry.Fee(2000).Height(16).FromTx(ref));
    signals.MempoolTransactionsRemovedForBlock(removed, 17);
    removed.clear(); // Nonempty notifications must retain their payload.
    bool reached_barrier{false};
    signals.CallFunctionInValidationInterfaceQueue([&] {
        reached_barrier = early->received.size() == 17 && late->received.size() == 17;
        signals.UnregisterSharedValidationInterface(early);
    });
    signals.MempoolTransactionsRemovedForBlock({}, 18);
    // Registration is observed when the callback executes, as for other events.
    signals.RegisterSharedValidationInterface(late);
    BOOST_CHECK(early->received.empty());
    BOOST_CHECK(late->received.empty());
    BOOST_CHECK_EQUAL(signals.CallbacksPending(), 19U);
    signals.FlushBackgroundCallbacks();
    BOOST_CHECK(reached_barrier);
    BOOST_REQUIRE_EQUAL(early->received.size(), 17U);
    BOOST_REQUIRE_EQUAL(late->received.size(), 18U);
    for (unsigned i{0}; i < late->received.size(); ++i) {
        BOOST_CHECK_EQUAL(late->received[i].first, i + 1);
        BOOST_CHECK_EQUAL(late->received[i].second.size(), i == 16 ? 1U : 0U);
    }
    BOOST_CHECK(late->received[16].second.front() == ref->GetHash());
    BOOST_CHECK(early->received == std::vector(late->received.begin(), late->received.end() - 1));
    BOOST_CHECK_EQUAL(signals.CallbacksPending(), 0U);
    signals.UnregisterAllValidationInterfaces();
}

BOOST_AUTO_TEST_SUITE_END()
