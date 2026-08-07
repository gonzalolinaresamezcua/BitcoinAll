// Copyright (c) 2025 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/btca_uptime.h>

#include <addresstype.h>
#include <consensus/btca.h>
#include <coins.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <util/strencodings.h>
#include <protocol.h>

#include <string>
#include <vector>

namespace {

bool ParseBtcaTimeTransaction(const CTransaction& tx, CKeyID& key_id_out, uint32_t& session_uptime_out, CAmount& reward_out)
{
    reward_out = 0;
    if (tx.vout.empty() || tx.vout[0].scriptPubKey.empty() || tx.vout[0].scriptPubKey[0] != OP_RETURN) {
        return false;
    }

    const CScript& script = tx.vout[0].scriptPubKey;
    std::vector<unsigned char> payload;
    opcodetype opcode;
    CScript::const_iterator pc = script.begin();
    if (!script.GetOp(pc, opcode) || opcode != OP_RETURN) return false;
    if (!script.GetOp(pc, opcode, payload) || pc != script.end()) return false;

    DataStream ss(std::span<const unsigned char>{payload});
    const std::string marker = "BTCA_TIME";
    std::string marker_read(marker.size(), '\0');
    if (ss.size() < marker.size()) return false;
    ss.read(std::span{(std::byte*)marker_read.data(), marker.size()});
    if (marker_read != marker) return false;

    uint8_t version;
    ss >> version;
    if (version != 0x01) return false;

    std::vector<unsigned char> pubkey_data(CPubKey::COMPRESSED_SIZE);
    ss.read(std::span{(std::byte*)pubkey_data.data(), pubkey_data.size()});
    CPubKey pubkey;
    pubkey.Set(pubkey_data.begin(), pubkey_data.end());
    if (!pubkey.IsFullyValid() || !pubkey.IsCompressed()) return false;
    key_id_out = pubkey.GetID();

    ss >> session_uptime_out;
    if (!ss.empty()) return false;

    if (tx.vout.size() == 3) {
        reward_out = tx.vout[1].nValue;
    }
    return true;
}

} // namespace

void ApplyBtcaUptimeFromTransaction(const CTransaction& tx, CCoinsViewCache& view)
{
    CKeyID key_id;
    uint32_t session_uptime = 0;
    CAmount reward = 0;
    if (!ParseBtcaTimeTransaction(tx, key_id, session_uptime, reward)) {
        return;
    }

    uint64_t previous_uptime = 0;
    view.GetUptime(key_id, previous_uptime);
    const uint64_t new_total_uptime = previous_uptime + session_uptime;
    view.SetUptime(key_id, new_total_uptime);

    if (reward > 0) {
        uint64_t last_rewarded = 0;
        view.GetLastRewardedUptime(key_id, last_rewarded);
        view.SetLastRewardedUptime(key_id, new_total_uptime);
        (void)last_rewarded;
    }
}
