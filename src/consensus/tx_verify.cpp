// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <util/check.h>
#include <util/moneystr.h>

// BTCA: Include headers for time transaction validation
#include <script/script.h>
#include <pubkey.h>
#include <streams.h>
#include <util/strencodings.h>
#include <keyaddress.h>     // For PKHash
#include <policy/policy.h> // For GetScriptForDestination
#include <chainparams.h>   // For COIN and potentially BTCA specific constants

// BTCA: Define constants for reward calculation (ideally from chainparams)
const CAmount BTCA_UPTIME_REWARD_AMOUNT_CONSENSUS = 100 * COIN;
const uint64_t BTCA_REWARD_INTERVAL_SECONDS_CONSENSUS = 24 * 60 * 60; // 24 hours

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;

    // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
    // transaction is still considered final if all inputs' nSequence ==
    // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
    //
    // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
    // also check that the spending input's nSequence != SEQUENCE_FINAL,
    // ensuring that an unsatisfied nLockTime value will actually cause
    // IsFinalTx() to return false here:
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height.  Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, uint32_t flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // If prev is coinbase, check that it's matured
        if (coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spend-of-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }
    }

    // BTCA: Logic for Time Transactions
    bool is_btca_time_tx_with_reward = false;
    CKeyID node_key_id_from_op_return;
    uint32_t session_uptime_from_op_return = 0;

    if (!tx.vout.empty() && tx.vout[0].scriptPubKey.IsOpReturn()) {
        const CScript& script = tx.vout[0].scriptPubKey;
        std::vector<unsigned char> data_op_return_payload;
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        if (script.GetOp(pc, opcode) && opcode == OP_RETURN) {
            if (script.GetOp(pc, opcode, data_op_return_payload) && pc == script.end()) {
                CDataStream ss(data_op_return_payload, SER_NETWORK, PROTOCOL_VERSION);
                std::string expected_marker = "BTCA_TIME";
                std::string marker_str(expected_marker.size(), '\\0');
                if (ss.size() >= expected_marker.size()) {
                    ss.read(marker_str.data(), expected_marker.size());
                    if (marker_str == expected_marker) {
                        // This is a BTCA_TIME transaction. Check if it has a reward.
                        // Basic structure validation (version, pubkey, extra data) is done in CheckTransaction.
                        // Here we only care if it's structured as a reward one (size == 3) for specific checks.
                        if (tx.vout.size() == 3) {
                             // Deserialize pubkey again to get KeyID for validation against reward output
                            try {
                                uint8_t version_dummy; // Already checked in CheckTransaction
                                CPubKey pubkey_dummy;  // Already checked in CheckTransaction
                                ss >> version_dummy; // Skip version
                                std::vector<unsigned char> pubkey_data(CPubKey::COMPRESSED_SIZE);
                                ss.read(pubkey_data.data(), pubkey_data.size());
                                pubkey_dummy.Set(pubkey_data.begin(), pubkey_data.end());
                                node_key_id_from_op_return = pubkey_dummy.GetID(); // Get KeyID
                                ss >> session_uptime_from_op_return; // Get session uptime
                                is_btca_time_tx_with_reward = true;
                            } catch (const std::ios_base::failure&) {
                                // This should not happen if CheckTransaction passed, but as a safeguard:
                                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-opreturn-corrupted-in-checktxinputs");
                            }
                        }
                    }
                }
            }
        }
    }

    CAmount value_out_for_fee_check = tx.GetValueOut();

    if (is_btca_time_tx_with_reward) {
        // For BTCA time transactions with rewards, the reward amount is not part of nValueIn.
        // It's "minted" by this transaction.
        // value_out_for_fee_check should only include non-reward outputs (OP_RETURN and dust).
        if (tx.vout.size() != 3) {
             // Should have been caught by CheckTransaction, but defensive check.
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-unexpected-vout-size");
        }
        value_out_for_fee_check = tx.vout[0].nValue + tx.vout[2].nValue; // OP_RETURN (0) + Dust

        // Validate the reward amount based on uptime state
        uint64_t previously_accumulated_uptime = 0;
        inputs.GetUptime(node_key_id_from_op_return, previously_accumulated_uptime);

        uint64_t last_rewarded_total_uptime = 0;
        inputs.GetLastRewardedUptime(node_key_id_from_op_return, last_rewarded_total_uptime);

        uint64_t current_total_uptime_if_connected = previously_accumulated_uptime + session_uptime_from_op_return;
        
        if (current_total_uptime_if_connected < last_rewarded_total_uptime) {
             // This could happen due to clock issues or reorgs where uptime was already rewarded for a higher value.
             // Or if session_uptime_from_op_return is negative, which should not happen.
             // Treat as no reward due.
             current_total_uptime_if_connected = last_rewarded_total_uptime;
        }

        uint64_t rewardable_uptime_seconds = current_total_uptime_if_connected - last_rewarded_total_uptime;
        uint64_t expected_reward_units = 0;

        if (rewardable_uptime_seconds >= BTCA_REWARD_INTERVAL_SECONDS_CONSENSUS) {
            expected_reward_units = rewardable_uptime_seconds / BTCA_REWARD_INTERVAL_SECONDS_CONSENSUS;
        }
        
        CAmount expected_reward_value = expected_reward_units * BTCA_UPTIME_REWARD_AMOUNT_CONSENSUS;

        if (tx.vout[1].nValue != expected_reward_value) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-amount-incorrect",
                strprintf("Incorrect reward amount. Expected %s, got %s", FormatMoney(expected_reward_value), FormatMoney(tx.vout[1].nValue)));
        }

        // Destination check already done in CheckTransaction, but can be re-verified for safety
        CScript expected_reward_script = GetScriptForDestination(PKHash(node_key_id_from_op_return));
        if (tx.vout[1].scriptPubKey != expected_reward_script) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-destination-mismatch-in-checktxinputs",
                "Reward output pays to incorrect destination (re-check)");
        }
    }

    if (nValueIn < value_out_for_fee_check) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s) for fee check", FormatMoney(nValueIn), FormatMoney(value_out_for_fee_check)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out_for_fee_check;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}
