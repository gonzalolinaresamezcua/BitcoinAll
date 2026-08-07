// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BTCA_H
#define BITCOIN_CONSENSUS_BTCA_H

#include <consensus/amount.h>

#include <cstdint>

/** PoU reward: 100 BTCA per 24 h of accumulated node uptime. */
static constexpr CAmount BTCA_UPTIME_REWARD_AMOUNT = 100 * COIN;
static constexpr uint64_t BTCA_REWARD_INTERVAL_SECONDS = 24 * 60 * 60;
static constexpr CAmount BTCA_MIN_DUST_OUTPUT_TO_SELF = 1;

#endif // BITCOIN_CONSENSUS_BTCA_H
