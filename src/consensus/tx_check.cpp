// Copyright (c) 2017-2021 The Bitcoin Core developers
// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <consensus/btca.h>
#include <consensus/btca_reward.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <script/script.h>
#include <addresstype.h>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    BtcaTimeTxData btca_data;
    const bool is_btca_time = ParseBtcaTimeTransaction(tx, btca_data);

    if (is_btca_time) {
        // PoU transactions use a single marker input with null prevout (no coinbase minting).
        if (tx.vin.size() != 1 || !tx.vin[0].prevout.IsNull()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-vin", "BTCA_TIME transaction must have exactly one null prevout marker input");
        }
        if (tx.IsCoinBase()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-coinbase", "BTCA_TIME transaction cannot be coinbase");
        }
        if (btca_data.session_uptime < BTCA_MIN_SESSION_UPTIME_SECONDS) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-uptime-too-short", "Session uptime below minimum for PoU participation");
        }

        const CScript expected_reward_script = GetScriptForDestination(PKHash(btca_data.key_id));
        if (btca_data.has_reward) {
            if (tx.vout[1].nValue <= 0) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-amount", "Reward amount must be positive");
            }
            if (tx.vout[1].scriptPubKey != expected_reward_script) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-dest", "Reward output pays to incorrect destination");
            }
            if (tx.vout[2].nValue < BTCA_MIN_DUST_OUTPUT_TO_SELF || tx.vout[2].nValue >= BTCA_UPTIME_REWARD_AMOUNT) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-dust-value", "Dust output for reward transaction has invalid value");
            }
            if (!tx.vout[2].scriptPubKey.empty() && tx.vout[2].scriptPubKey[0] == OP_RETURN) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-dust-type", "Dust output for reward transaction is OP_RETURN");
            }
        } else if (tx.vout.size() == 2) {
            if (tx.vout[1].nValue < BTCA_MIN_DUST_OUTPUT_TO_SELF || tx.vout[1].nValue >= BTCA_UPTIME_REWARD_AMOUNT) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-simple-dust-value", "Dust output for simple time transaction has invalid value");
            }
            if (!tx.vout[1].scriptPubKey.empty() && tx.vout[1].scriptPubKey[0] == OP_RETURN) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-simple-dust-type", "Dust output for simple time transaction is OP_RETURN");
            }
        } else {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-vout-count", "Time transaction has incorrect number of outputs (must be 2 or 3)");
        }
        return true;
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}
