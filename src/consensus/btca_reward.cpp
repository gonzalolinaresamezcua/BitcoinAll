// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/btca_reward.h>

#include <consensus/btca.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>

#include <algorithm>

namespace {

constexpr std::string_view BTCA_TIME_MARKER = "BTCA_TIME";

bool ReadMarker(DataStream& ss)
{
    if (ss.size() < BTCA_TIME_MARKER.size()) return false;
    std::string marker(BTCA_TIME_MARKER.size(), '\0');
    ss.read(std::span{(std::byte*)marker.data(), marker.size()});
    return marker == BTCA_TIME_MARKER;
}

bool ExtractOpReturnPayload(const CTransaction& tx, std::vector<unsigned char>& payload_out)
{
    if (tx.vout.empty() || tx.vout[0].scriptPubKey.empty() || tx.vout[0].scriptPubKey[0] != OP_RETURN) {
        return false;
    }
    const CScript& script = tx.vout[0].scriptPubKey;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, payload_out) || pc != script.end()) return false;
    return true;
}

} // namespace

bool IsBtcaTimeTransaction(const CTransaction& tx)
{
    std::vector<unsigned char> payload;
    if (!ExtractOpReturnPayload(tx, payload)) return false;
    DataStream ss(std::span<const unsigned char>{payload});
    return ReadMarker(ss);
}

bool ParseBtcaTimeTransaction(const CTransaction& tx, BtcaTimeTxData& out)
{
    out = BtcaTimeTxData{};
    std::vector<unsigned char> payload;
    if (!ExtractOpReturnPayload(tx, payload)) return false;

    DataStream ss(std::span<const unsigned char>{payload});
    if (!ReadMarker(ss)) return false;

    try {
        ss >> out.version;
        if (out.version != BTCA_POU_VERSION_LEGACY && out.version != BTCA_POU_VERSION) {
            return false;
        }

        std::vector<unsigned char> pubkey_data(CPubKey::COMPRESSED_SIZE);
        ss.read(std::span{(std::byte*)pubkey_data.data(), pubkey_data.size()});
        CPubKey pubkey;
        pubkey.Set(pubkey_data.begin(), pubkey_data.end());
        if (!pubkey.IsFullyValid() || !pubkey.IsCompressed()) return false;
        out.key_id = pubkey.GetID();

        ss >> out.session_uptime;

        out.peer_count = BTCA_MIN_PEER_COUNT;
        if (out.version == BTCA_POU_VERSION) {
            ss >> out.peer_count;
            uint8_t attested_count = 0;
            ss >> attested_count;
            if (attested_count > BTCA_MAX_ATTESTED_PEERS) return false;
            out.attested_peers.reserve(attested_count);
            for (uint8_t i = 0; i < attested_count; ++i) {
                uint160 raw_id;
                ss.read(std::span{(std::byte*)raw_id.begin(), raw_id.size()});
                out.attested_peers.emplace_back(raw_id);
            }
        }

        if (!ss.empty()) return false;
    } catch (const std::ios_base::failure&) {
        return false;
    }

    if (out.peer_count < BTCA_MIN_PEER_COUNT || out.peer_count > BTCA_MAX_PEER_COUNT) {
        return false;
    }
    if (out.attested_peers.size() > out.peer_count) {
        return false;
    }

    out.is_btca_time = true;
    out.has_reward = tx.vout.size() == 3;
    if (out.has_reward) {
        out.claimed_reward = tx.vout[1].nValue;
    }
    return true;
}

uint64_t GetBtcaScaledRewardInterval(uint16_t peer_count)
{
    const uint16_t effective_peers = std::clamp(peer_count, BTCA_MIN_PEER_COUNT, BTCA_MAX_PEER_COUNT);
    return BTCA_REWARD_INTERVAL_SECONDS * static_cast<uint64_t>(effective_peers);
}

CAmount CalculateExpectedBtcaReward(const BtcaTimeTxData& data, const CCoinsViewCache& view)
{
    if (!data.has_reward) return 0;

    uint64_t previously_accumulated_uptime = 0;
    view.GetUptime(data.key_id, previously_accumulated_uptime);

    uint64_t last_rewarded_total_uptime = 0;
    view.GetLastRewardedUptime(data.key_id, last_rewarded_total_uptime);

    uint64_t current_total_uptime = previously_accumulated_uptime + data.session_uptime;
    if (current_total_uptime < last_rewarded_total_uptime) {
        current_total_uptime = last_rewarded_total_uptime;
    }

    const uint64_t rewardable_uptime = current_total_uptime - last_rewarded_total_uptime;
    const uint64_t interval = GetBtcaScaledRewardInterval(data.peer_count);
    uint64_t reward_units = 0;
    if (interval > 0 && rewardable_uptime >= interval) {
        reward_units = rewardable_uptime / interval;
    }

    CAmount expected = reward_units * BTCA_UPTIME_REWARD_AMOUNT;
    if (last_rewarded_total_uptime == 0) {
        expected += BTCA_WELCOME_REWARD_AMOUNT;
    }
    return expected;
}

std::vector<unsigned char> BuildBtcaTimePayload(const CPubKey& pubkey,
                                                uint32_t session_uptime,
                                                uint16_t peer_count,
                                                const std::vector<CKeyID>& attested_peers)
{
    std::vector<unsigned char> payload;
    DataStream ss;
    ss.write(std::span{(const std::byte*)BTCA_TIME_MARKER.data(), BTCA_TIME_MARKER.size()});
    ss << BTCA_POU_VERSION;
    ss.write(std::span{(const std::byte*)pubkey.data(), pubkey.size()});
    ss << session_uptime;
    ss << peer_count;
    const uint8_t attested_count = static_cast<uint8_t>(std::min<size_t>(attested_peers.size(), BTCA_MAX_ATTESTED_PEERS));
    ss << attested_count;
    for (uint8_t i = 0; i < attested_count; ++i) {
        ss.write(std::span{(const std::byte*)attested_peers[i].begin(), attested_peers[i].size()});
    }
    payload.reserve(ss.size());
    for (auto it = ss.begin(); it != ss.end(); ++it) {
        payload.push_back(static_cast<unsigned char>(*it));
    }
    return payload;
}
