// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BTCA_REWARD_H
#define BITCOIN_CONSENSUS_BTCA_REWARD_H

#include <consensus/amount.h>
#include <pubkey.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class CCoinsViewCache;
class CTransaction;

struct BtcaTimeTxData
{
    bool is_btca_time{false};
    bool has_reward{false};
    uint8_t version{0};
    CKeyID key_id;
    uint32_t session_uptime{0};
    uint16_t peer_count{1};
    std::vector<CKeyID> attested_peers;
    CAmount claimed_reward{0};
};

/** Returns true if tx.vout[0] carries a BTCA_TIME OP_RETURN payload. */
bool IsBtcaTimeTransaction(const CTransaction& tx);

/** Parse BTCA_TIME structure from a transaction. */
bool ParseBtcaTimeTransaction(const CTransaction& tx, BtcaTimeTxData& out);

/** Reward interval grows with peer count to control network inflation. */
uint64_t GetBtcaScaledRewardInterval(uint16_t peer_count);

/** Expected minted reward (welcome + uptime) for a reward-bearing BTCA_TIME tx. */
CAmount CalculateExpectedBtcaReward(const BtcaTimeTxData& data, const CCoinsViewCache& view);

/** Build OP_RETURN payload for BTCA_TIME v0x02. */
std::vector<unsigned char> BuildBtcaTimePayload(const CPubKey& pubkey,
                                                uint32_t session_uptime,
                                                uint16_t peer_count,
                                                const std::vector<CKeyID>& attested_peers);

#endif // BITCOIN_CONSENSUS_BTCA_REWARD_H
