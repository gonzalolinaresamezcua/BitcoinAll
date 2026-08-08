// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/btca_uptime.h>

#include <consensus/btca_reward.h>
#include <coins.h>
#include <primitives/transaction.h>

void ApplyBtcaUptimeFromTransaction(const CTransaction& tx, CCoinsViewCache& view)
{
    BtcaTimeTxData data;
    if (!ParseBtcaTimeTransaction(tx, data)) {
        return;
    }

    uint64_t previous_uptime = 0;
    view.GetUptime(data.key_id, previous_uptime);
    const uint64_t new_total_uptime = previous_uptime + data.session_uptime;
    view.SetUptime(data.key_id, new_total_uptime);

    if (data.has_reward && data.claimed_reward > 0) {
        view.SetLastRewardedUptime(data.key_id, new_total_uptime);
    }
}
