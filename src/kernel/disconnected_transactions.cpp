// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/disconnected_transactions.h>

#include <cassert>
#include <core_memusage.h>
#include <memusage.h>
#include <primitives/transaction.h>
#include <util/hasher.h>

#include <memory>
#include <utility>

// It's almost certainly a logic bug if we don't clear out queuedTx before
// destruction, as we add to it while disconnecting blocks, and then we
// need to re-process remaining transactions to ensure mempool consistency.
// For now, assert() that we've emptied out this object on destruction.
// This assert() can always be removed if the reorg-processing code were
// to be refactored such that this assumption is no longer true (for
// instance if there was some other way we cleaned up the mempool after a
// reorg, besides draining this object).
DisconnectedBlockTransactions::~DisconnectedBlockTransactions()
{
    assert(queuedTx.empty());
#if defined(__APPLE__) && defined(__x86_64__)
    assert(!m_iters_by_txid || m_iters_by_txid->empty());
#else
    assert(iters_by_txid.empty());
#endif
    assert(cachedInnerUsage == 0);
}

std::vector<CTransactionRef> DisconnectedBlockTransactions::LimitMemoryUsage()
{
    std::vector<CTransactionRef> evicted;
#if defined(__APPLE__) && defined(__x86_64__)
    if (!m_iters_by_txid) {
        assert(queuedTx.empty());
        assert(cachedInnerUsage == 0);
        return evicted;
    }
    auto& iters_by_txid{*m_iters_by_txid};
#endif

    while (!queuedTx.empty() && DynamicMemoryUsage() > m_max_mem_usage) {
        evicted.emplace_back(queuedTx.front());
        cachedInnerUsage -= RecursiveDynamicUsage(queuedTx.front());
        iters_by_txid.erase(queuedTx.front()->GetHash());
        queuedTx.pop_front();
    }
    return evicted;
}

size_t DisconnectedBlockTransactions::DynamicMemoryUsage() const
{
#if defined(__APPLE__) && defined(__x86_64__)
    const size_t index_usage{m_iters_by_txid ? memusage::DynamicUsage(*m_iters_by_txid) : 0};
    return cachedInnerUsage + index_usage + memusage::DynamicUsage(queuedTx);
#else
    return cachedInnerUsage + memusage::DynamicUsage(iters_by_txid) + memusage::DynamicUsage(queuedTx);
#endif
}

[[nodiscard]] std::vector<CTransactionRef> DisconnectedBlockTransactions::AddTransactionsFromBlock(const std::vector<CTransactionRef>& vtx)
{
#if defined(__APPLE__) && defined(__x86_64__)
    if (!m_iters_by_txid) {
        if (vtx.empty()) return LimitMemoryUsage();
        m_iters_by_txid.emplace();
    }
    auto& iters_by_txid{*m_iters_by_txid};
#endif
    iters_by_txid.reserve(iters_by_txid.size() + vtx.size());
    for (auto block_it = vtx.rbegin(); block_it != vtx.rend(); ++block_it) {
        auto it = queuedTx.insert(queuedTx.end(), *block_it);
        auto [_, inserted] = iters_by_txid.emplace((*block_it)->GetHash(), it);
        assert(inserted); // callers may never pass multiple transactions with the same txid
        cachedInnerUsage += RecursiveDynamicUsage(*block_it);
    }
    return LimitMemoryUsage();
}

void DisconnectedBlockTransactions::removeForBlock(const std::vector<CTransactionRef>& vtx)
{
    // Short-circuit in the common case of a block being added to the tip
    if (queuedTx.empty()) {
        return;
    }
#if defined(__APPLE__) && defined(__x86_64__)
    assert(m_iters_by_txid.has_value());
    auto& iters_by_txid{*m_iters_by_txid};
#endif
    for (const auto& tx : vtx) {
        auto iter = iters_by_txid.find(tx->GetHash());
        if (iter != iters_by_txid.end()) {
            auto list_iter = iter->second;
            iters_by_txid.erase(iter);
            cachedInnerUsage -= RecursiveDynamicUsage(*list_iter);
            queuedTx.erase(list_iter);
        }
    }
}

void DisconnectedBlockTransactions::clear()
{
    cachedInnerUsage = 0;
#if defined(__APPLE__) && defined(__x86_64__)
    if (m_iters_by_txid) m_iters_by_txid->clear();
#else
    iters_by_txid.clear();
#endif
    queuedTx.clear();
}

std::list<CTransactionRef> DisconnectedBlockTransactions::take()
{
    std::list<CTransactionRef> ret = std::move(queuedTx);
    clear();
    return ret;
}
