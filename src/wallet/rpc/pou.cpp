// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <common/system.h>
#include <consensus/btca.h>
#include <consensus/btca_reward.h>
#include <core_io.h>
#include <interfaces/mining.h>
#include <key_io.h>
#include <net.h>
#include <netmessagemaker.h>
#include <node/context.h>
#include <node/pou_block.h>
#include <node/pou_peers.h>
#include <node/transaction.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/script.h>
#include <util/bitcoin_time.h>
#include <util/chaintype.h>
#include <validation.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <algorithm>
#include <univalue.h>

using node::BroadcastTransaction;
using node::NodeContext;
using node::TransactionError;

namespace wallet {

static CPubKey GetWalletPubKeyForAddress(const CWallet& wallet, const CTxDestination& dest)
{
    CKeyID key_id;
    if (const PKHash* pkhash = std::get_if<PKHash>(&dest)) {
        key_id = ToKeyID(*pkhash);
    } else if (const WitnessV0KeyHash* wit = std::get_if<WitnessV0KeyHash>(&dest)) {
        key_id = CKeyID{uint160{*wit}};
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Address must be P2PKH or P2WPKH");
    }
    const CScript script = GetScriptForDestination(dest);

    for (ScriptPubKeyMan* spkm : wallet.GetAllScriptPubKeyMans()) {
        if (auto provider = spkm->GetSolvingProvider(script)) {
            CPubKey pubkey;
            if (provider->GetPubKey(key_id, pubkey)) {
                return pubkey;
            }
        }
    }
    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Wallet does not control this address");
}

static void BroadcastPouAnnouncement(CConnman& connman, const CPubKey& pubkey)
{
    connman.ForEachNode([&](CNode* pnode) {
        const std::vector<unsigned char> pubkey_data(pubkey.begin(), pubkey.begin() + pubkey.size());
        connman.PushMessage(pnode, NetMsg::Make(NetMsgType::POUANNOUNCE, pubkey_data));
        return true;
    });
}

static uint16_t ComputeEffectivePeerCount(const CConnman& connman)
{
    const int connections = connman.GetNodeCount(ConnectionDirection::Both);
    return static_cast<uint16_t>(std::clamp(connections + 1, int(BTCA_MIN_PEER_COUNT), int(BTCA_MAX_PEER_COUNT)));
}

static CMutableTransaction BuildBtcaTimeTransaction(const CPubKey& pubkey,
                                                     uint32_t session_uptime,
                                                     uint16_t peer_count,
                                                     const std::vector<CKeyID>& attested_peers,
                                                     CAmount reward_amount)
{
    CMutableTransaction mtx;
    mtx.vin.emplace_back(); // PoU marker input (null prevout)

    const std::vector<unsigned char> payload = BuildBtcaTimePayload(pubkey, session_uptime, peer_count, attested_peers);
    CScript op_return;
    op_return << OP_RETURN << payload;
    mtx.vout.emplace_back(0, op_return);

    const CScript payout = GetScriptForDestination(PKHash(pubkey.GetID()));
    if (reward_amount > 0) {
        mtx.vout.emplace_back(reward_amount, payout);
        mtx.vout.emplace_back(BTCA_MIN_DUST_OUTPUT_TO_SELF, payout);
    } else {
        mtx.vout.emplace_back(BTCA_MIN_DUST_OUTPUT_TO_SELF, payout);
    }
    return mtx;
}

RPCHelpMan announcepou()
{
    return RPCHelpMan{"announcepou",
        "\nBroadcast this wallet's PoU identity to connected peers.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "BTCA address whose public key is announced."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "key_id", "Announced node KeyID"},
        }},
        RPCExamples{HelpExampleCli("announcepou", "\"myaddress\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<const CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            NodeContext& node = EnsureAnyNodeContext(request.context);
            CConnman& connman = EnsureConnman(node);

            LOCK(pwallet->cs_wallet);
            const CTxDestination dest = DecodeDestination(self.Arg<std::string>("address"));
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            const CPubKey pubkey = GetWalletPubKeyForAddress(*pwallet, dest);
            BroadcastPouAnnouncement(connman, pubkey);

            UniValue result(UniValue::VOBJ);
            result.pushKV("key_id", pubkey.GetID().ToString());
            return result;
        },
    };
}

RPCHelpMan submitpouclaim()
{
    return RPCHelpMan{"submitpouclaim",
        "\nClaim PoU rewards by creating a BTCA_TIME transaction and mining a zero-subsidy block.\n"
        "Emits the welcome bonus (50 BTCA) once, then uptime rewards scaled by peer count.\n",
        {
            {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "BTCA address to receive the PoU reward."},
            {"mine_block", RPCArg::Type::BOOL, RPCArg::Default{true}, "Mine a block including the PoU transaction."},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "txid", "PoU transaction id"},
            {RPCResult::Type::STR_HEX, "blockhash", /*optional=*/true, "Block hash if mined locally"},
            {RPCResult::Type::NUM, "reward_amount", "Claimed reward in BTCA"},
            {RPCResult::Type::NUM, "peer_count", "Peer count used for inflation scaling"},
        }},
        RPCExamples{
            HelpExampleCli("announcepou", "\"myaddress\"")
            + HelpExampleCli("submitpouclaim", "\"myaddress\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            const std::shared_ptr<CWallet> pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return UniValue::VNULL;

            NodeContext& node = EnsureAnyNodeContext(request.context);
            ChainstateManager& chainman = EnsureAnyChainman(request.context);
            CConnman& connman = EnsureConnman(node);
            interfaces::Mining& miner = EnsureMining(node);

            LOCK(pwallet->cs_wallet);
            LOCK(cs_main);

            const CTxDestination dest = DecodeDestination(self.Arg<std::string>("address"));
            if (!IsValidDestination(dest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            const CPubKey pubkey = GetWalletPubKeyForAddress(*pwallet, dest);

            const int64_t session_start = node.m_session_start_time.load();
            if (session_start <= 0) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Session start time unavailable");
            }
            const uint32_t session_uptime = static_cast<uint32_t>(std::max<int64_t>(0, GetTime() - session_start));
            if (session_uptime < BTCA_MIN_SESSION_UPTIME_SECONDS) {
                throw JSONRPCError(RPC_MISC_ERROR, strprintf("Session uptime %u s is below minimum %u s", session_uptime, BTCA_MIN_SESSION_UPTIME_SECONDS));
            }

            const uint16_t peer_count = ComputeEffectivePeerCount(connman);
            std::vector<CKeyID> attested = ListAnnouncedPouPeerKeyIDs();
            if (attested.size() > BTCA_MAX_ATTESTED_PEERS) {
                attested.resize(BTCA_MAX_ATTESTED_PEERS);
            }

            BroadcastPouAnnouncement(connman, pubkey);

            CCoinsViewCache& view = chainman.ActiveChainstate().CoinsTip();
            BtcaTimeTxData preview;
            preview.key_id = pubkey.GetID();
            preview.session_uptime = session_uptime;
            preview.peer_count = peer_count;
            preview.attested_peers = attested;
            preview.has_reward = true;

            const CAmount expected_reward = CalculateExpectedBtcaReward(preview, view);
            if (expected_reward <= 0) {
                throw JSONRPCError(RPC_MISC_ERROR, "No PoU reward is currently due");
            }

            CMutableTransaction mtx = BuildBtcaTimeTransaction(pubkey, session_uptime, peer_count, attested, expected_reward);
            const CTransactionRef tx = MakeTransactionRef(std::move(mtx));

            UniValue result(UniValue::VOBJ);
            result.pushKV("txid", tx->GetHash().GetHex());
            result.pushKV("reward_amount", ValueFromAmount(expected_reward));
            result.pushKV("peer_count", peer_count);

            const bool mine_block = self.Arg<bool>("mine_block");
            if (mine_block) {
                const CScript coinbase_script = GetScriptForDestination(dest);
                uint256 block_hash;
                std::string mine_error;
                if (!MineBlockIncludingPoUTx(chainman, miner, tx, coinbase_script, block_hash, mine_error)) {
                    throw JSONRPCError(RPC_MISC_ERROR, mine_error);
                }
                result.pushKV("blockhash", block_hash.GetHex());
            } else {
                std::string err;
                const TransactionError err_code = BroadcastTransaction(node, tx, err, /*max_tx_fee=*/0, /*relay=*/true, /*wait_callback=*/false);
                if (err_code != TransactionError::OK) {
                    throw JSONRPCError(RPC_TRANSACTION_ERROR, err);
                }
            }
            return result;
        },
    };
}

} // namespace wallet
