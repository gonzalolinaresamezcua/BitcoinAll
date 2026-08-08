// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BTCA_H
#define BITCOIN_CONSENSUS_BTCA_H

#include <consensus/amount.h>

#include <cstdint>

/** One-time welcome reward for first PoU claim. */
static constexpr CAmount BTCA_WELCOME_REWARD_AMOUNT = 50 * COIN;

/** PoU uptime reward: 100 BTCA per scaled interval of accumulated node uptime. */
static constexpr CAmount BTCA_UPTIME_REWARD_AMOUNT = 100 * COIN;

/** Base reward interval (24 h) before peer-count scaling. */
static constexpr uint64_t BTCA_REWARD_INTERVAL_SECONDS = 24 * 60 * 60;

/** Minimum dust output sent back to self in BTCA_TIME transactions. */
static constexpr CAmount BTCA_MIN_DUST_OUTPUT_TO_SELF = 1;

/** BTCA_TIME payload versions. v0x01 is legacy (peer_count assumed 1). */
static constexpr uint8_t BTCA_POU_VERSION_LEGACY = 0x01;
static constexpr uint8_t BTCA_POU_VERSION = 0x02;

/** Peer count bounds used for inflation scaling. */
static constexpr uint16_t BTCA_MIN_PEER_COUNT = 1;
static constexpr uint16_t BTCA_MAX_PEER_COUNT = 1000;

/** Maximum attested peers embedded in a BTCA_TIME v0x02 transaction. */
static constexpr uint8_t BTCA_MAX_ATTESTED_PEERS = 32;

/** Minimum session uptime (seconds) before a reward claim is allowed. */
static constexpr uint32_t BTCA_MIN_SESSION_UPTIME_SECONDS = 60;

#endif // BITCOIN_CONSENSUS_BTCA_H
