// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_POU_BLOCK_H
#define BITCOIN_NODE_POU_BLOCK_H

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <string>

class ChainstateManager;
namespace interfaces {
class Mining;
}

/** Mine a zero-subsidy block that includes a PoU transaction (mainnet block production). */
bool MineBlockIncludingPoUTx(ChainstateManager& chainman,
                             interfaces::Mining& miner,
                             const CTransactionRef& pou_tx,
                             const CScript& coinbase_output_script,
                             uint256& block_hash_out,
                             std::string& error_out);

#endif // BITCOIN_NODE_POU_BLOCK_H
