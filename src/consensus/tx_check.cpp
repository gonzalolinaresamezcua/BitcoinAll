// Copyright (c) 2017-2021 The Bitcoin Core developers
// Copyright (c) 2025 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>
#include <script/script.h>
#include <pubkey.h>
#include <key_io.h>
#include <policy/policy.h>
#include <streams.h>
#include <util/strencodings.h>
#include <serialize.h>
#include <protocol.h>
#include <node/protocol_version.h>
#include <span>

// BTCA: Define constants for reward and dust amounts
// These should ideally be part of consensus params or a shared constants file
// For now, defining them here for clarity.
const CAmount BTCA_UPTIME_REWARD_AMOUNT = 100 * COIN; // 100 BTCA per reward unit
const CAmount BTCA_MIN_DUST_OUTPUT_TO_SELF = 1; // 1 satoshi

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
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

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
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

    // BTCA: Validation for "Connection Time" transactions
    // Check if the first output's scriptPubKey starts with OP_RETURN
    if (!tx.vout.empty() && !tx.vout[0].scriptPubKey.empty() && tx.vout[0].scriptPubKey[0] == OP_RETURN) {
        const CScript& script = tx.vout[0].scriptPubKey;
        std::vector<unsigned char> data_op_return_payload; // Renamed to avoid conflict with 'data' from GetOp
        opcodetype opcode;
        CScript::const_iterator pc = script.begin();
        // Check if the first opcode is OP_RETURN (redundant with above but good practice for iterator usage)
        if (script.GetOp(pc, opcode) && opcode == OP_RETURN) {
            // Check if there is a single data push after OP_RETURN
            if (script.GetOp(pc, opcode, data_op_return_payload)) { // Get the actual data push
                // Ensure no more opcodes after the data push for a standard OP_RETURN
                if (pc == script.end()) {
                    // BTCA: Construct DataStream with a span
                    DataStream ss(std::span<const unsigned char>{data_op_return_payload});
                    std::string expected_marker = "BTCA_TIME";
                    std::string marker_str(expected_marker.size(), '\0');

                    if (ss.size() >= expected_marker.size()) {
                        ss.read(std::span{(std::byte*)marker_str.data(), expected_marker.size()});
                        if (marker_str == expected_marker) {
                            // Marker found, this is a BTCA Time Transaction.
                            uint8_t version;
                            CPubKey pubkey_from_op_return;
                            CKeyID key_id_from_op_return;
                            uint32_t uptime_seconds;

                            try {
                                ss >> version;
                                if (version != 0x01) {
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-version", "Time transaction has incorrect version");
                                }

                                std::vector<unsigned char> pubkey_data_vec(CPubKey::COMPRESSED_SIZE);
                                ss.read(std::span{(std::byte*)pubkey_data_vec.data(), pubkey_data_vec.size()});
                                pubkey_from_op_return.Set(pubkey_data_vec.begin(), pubkey_data_vec.end());

                                if (!pubkey_from_op_return.IsFullyValid() || !pubkey_from_op_return.IsCompressed()) {
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-pubkey", "Time transaction has invalid or uncompressed pubkey");
                                }
                                key_id_from_op_return = pubkey_from_op_return.GetID();

                                ss >> uptime_seconds; // Uptime, no specific validation for now beyond deserialization
                            } catch (const std::ios_base::failure&) {
                                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-deserialize", "Failed to deserialize time transaction OP_RETURN data");
                            }

                            if (!ss.empty()) {
                                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-extra-data", "Extra data found in time transaction OP_RETURN");
                            }

                            // Now validate the outputs based on whether it's a reward transaction or just a time record
                            if (tx.vout.size() == 3) { // With reward: OP_RETURN, Reward Output, Dust Output
                                // Validate Reward Output (vout[1])
                                if (tx.vout[1].nValue <= 0 || tx.vout[1].nValue % BTCA_UPTIME_REWARD_AMOUNT != 0) {
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-amount-indivisible", "Reward amount is not a positive multiple of standard reward unit");
                                }
                                CScript expected_reward_script = GetScriptForDestination(PKHash(key_id_from_op_return));
                                if (tx.vout[1].scriptPubKey != expected_reward_script) {
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-dest", "Reward output pays to incorrect destination");
                                }

                                // Validate Dust Output (vout[2])
                                if (tx.vout[2].nValue < BTCA_MIN_DUST_OUTPUT_TO_SELF || tx.vout[2].nValue >= BTCA_UPTIME_REWARD_AMOUNT) { // Should be small, definitely not a reward
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-dust-value", "Dust output for reward transaction has invalid value");
                                }
                                // BTCA: Check if dust output scriptPubKey is OP_RETURN
                                if (!tx.vout[2].scriptPubKey.empty() && tx.vout[2].scriptPubKey[0] == OP_RETURN) { // Cannot be another OP_RETURN
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-reward-dust-type", "Dust output for reward transaction is OP_RETURN");
                                }

                            } else if (tx.vout.size() == 2) { // No reward: OP_RETURN, Dust Output
                                // Validate Dust Output (vout[1])
                                if (tx.vout[1].nValue < BTCA_MIN_DUST_OUTPUT_TO_SELF || tx.vout[1].nValue >= BTCA_UPTIME_REWARD_AMOUNT) { // Should be small
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-simple-dust-value", "Dust output for simple time transaction has invalid value");
                                }
                                 // BTCA: Check if dust output scriptPubKey is OP_RETURN
                                if (!tx.vout[1].scriptPubKey.empty() && tx.vout[1].scriptPubKey[0] == OP_RETURN) { // Cannot be another OP_RETURN
                                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-simple-dust-type", "Dust output for simple time transaction is OP_RETURN");
                                }
                            } else {
                                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-btca-time-tx-vout-count", "Time transaction has incorrect number of outputs (must be 2 or 3)");
                            }
                            // If we reached here, the BTCA_TIME transaction is valid according to these checks.
                            // Return true as other basic checks (vin not empty, vout not empty, size, negative/overflow, duplicate inputs)
                            // have already passed. Coinbase specific checks are also handled.
                            return true;
                        }
                    }
                }
            }
        }
    }

    // Standard transaction checks (if not a BTCA_TIME transaction or if BTCA_TIME checks passed without returning)
    // The original code had:
    // if (tx.IsCoinBase()) { ... } else { for (const auto& txin : tx.vin) if (txin.prevout.IsNull()) ... }
    // This was already covered at the start of the function.
    // The remaining logic in the original function after time transaction checks was just 'return true;'.
    // All necessary checks for non-time transactions (and basic checks for time transactions)
    // should have been performed before the BTCA_TIME specific block.

    return true;
}
