// Copyright (c) 2023-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit.

#ifndef BITCOIN_NODE_PEERMAN_ARGS_H
#define BITCOIN_NODE_PEERMAN_ARGS_H

#include <net_processing.h>

#include <cstdint>

class ArgsManager;
enum class ChainType;

namespace node {
void ApplyArgsManOptions(const ArgsManager& argsman, PeerManager::Options& options, ChainType chain, uint64_t total_ram);
} // namespace node

#endif // BITCOIN_NODE_PEERMAN_ARGS_H
