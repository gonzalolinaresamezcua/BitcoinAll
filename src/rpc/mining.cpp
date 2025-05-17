// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <chain.h>
#include <chainparams.h>
#include <chainparamsbase.h>
#include <common/system.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deploymentinfo.h>
#include <deploymentstatus.h>
#include <interfaces/mining.h>
#include <key_io.h>
#include <net.h>
#include <node/context.h>
#include <node/miner.h>
#include <node/warnings.h>
#include <policy/ephemeral_policy.h>
#include <pow.h>
#include <rpc/blockchain.h>
#include <rpc/mining.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <txmempool.h>
#include <univalue.h>
#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <memory>
#include <stdint.h>
#include <key.h>

using interfaces::BlockRef;
using interfaces::BlockTemplate;
using interfaces::Mining;
using node::BlockAssembler;
using node::GetMinimumTime;
using node::NodeContext;
using node::RegenerateCommitments;
using node::UpdateTime;
using util::ToString;

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is -1.
 * If 'height' is -1, compute the estimate from current chain tip.
 * If 'height' is a valid block height, compute the estimate at the time when a given block was found.
 */
static UniValue GetNetworkHashPS(int lookup, int height, const CChain& active_chain) {
    if (lookup < -1 || lookup == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nblocks. Must be a positive number or -1.");
    }

    if (height < -1 || height > active_chain.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block does not exist at specified height");
    }

    const CBlockIndex* pb = active_chain.Tip();

    if (height >= 0) {
        pb = active_chain[height];
    }

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If lookup is -1, then use blocks since last difficulty change.
    if (lookup == -1)
        lookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If lookup is larger than chain, then set it to chain length.
    if (lookup > pb->nHeight)
        lookup = pb->nHeight;

    const CBlockIndex* pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < lookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

static RPCHelpMan getnetworkhashps()
{
    return RPCHelpMan{"getnetworkhashps",
                "\nReturns the estimated network hashes per second based on the last n blocks.\n"
                "Pass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\n"
                "Pass in [height] to estimate the network speed at the time when a certain block was found.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120}, "The number of previous blocks to calculate estimate from, or -1 for blocks since last difficulty change."},
                    {"height", RPCArg::Type::NUM, RPCArg::Default{-1}, "To estimate at the time of the given height."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Hashes per second estimated"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    LOCK(cs_main);
    return GetNetworkHashPS(self.Arg<int>("nblocks"), self.Arg<int>("height"), chainman.ActiveChain());
},
    };
}

static bool GenerateBlock(ChainstateManager& chainman, CBlock&& block, uint64_t& max_tries, std::shared_ptr<const CBlock>& block_out, bool process_new_block)
{
    block_out.reset();
    block.hashMerkleRoot = BlockMerkleRoot(block);

    if (chainman.m_interrupt) {
        return false;
    }

    if (max_tries == 0) {
        return false;
    }

    block_out = std::make_shared<const CBlock>(std::move(block));

    if (!process_new_block) return true;

    if (!chainman.ProcessNewBlock(block_out, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "ProcessNewBlock, block not accepted");
    }

    return true;
}

static UniValue generateBlocks(ChainstateManager& chainman, Mining& miner, const CScript& coinbase_output_script, int nGenerate, uint64_t nMaxTries)
{
    UniValue blockHashes(UniValue::VARR);
    while (nGenerate > 0 && !chainman.m_interrupt) {
        std::unique_ptr<BlockTemplate> block_template(miner.createNewBlock({ .coinbase_output_script = coinbase_output_script }));
        CHECK_NONFATAL(block_template);

        std::shared_ptr<const CBlock> block_out;
        if (!GenerateBlock(chainman, block_template->getBlock(), nMaxTries, block_out, /*process_new_block=*/true)) {
            break;
        }

        if (block_out) {
            --nGenerate;
            blockHashes.push_back(block_out->GetHash().GetHex());
        }
    }
    return blockHashes;
}

static bool getScriptFromDescriptor(const std::string& descriptor, CScript& script, std::string& error)
{
    FlatSigningProvider key_provider;
    const auto descs = Parse(descriptor, key_provider, error, /* require_checksum = */ false);
    if (descs.empty()) return false;
    if (descs.size() > 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Multipath descriptor not accepted");
    }
    const auto& desc = descs.at(0);
    if (desc->IsRange()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Ranged descriptor not accepted. Maybe pass through deriveaddresses first?");
    }

    FlatSigningProvider provider;
    std::vector<CScript> scripts;
    if (!desc->Expand(0, key_provider, scripts, provider)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Cannot derive script without private keys");
    }

    // Combo descriptors can have 2 or 4 scripts, so we can't just check scripts.size() == 1
    CHECK_NONFATAL(scripts.size() > 0 && scripts.size() <= 4);

    if (scripts.size() == 1) {
        script = scripts.at(0);
    } else if (scripts.size() == 4) {
        // For uncompressed keys, take the 3rd script, since it is p2wpkh
        script = scripts.at(2);
    } else {
        // Else take the 2nd script, since it is p2pkh
        script = scripts.at(1);
    }

    return true;
}

static RPCHelpMan generatetodescriptor()
{
    return RPCHelpMan{
        "generatetodescriptor",
        "Mine to a specified descriptor and return the block hashes.",
        {
            {"num_blocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
            {"descriptor", RPCArg::Type::STR, RPCArg::Optional::NO, "The descriptor to send the newly generated bitcoin to."},
            {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
        },
        RPCResult{
            RPCResult::Type::ARR, "", "hashes of blocks generated",
            {
                {RPCResult::Type::STR_HEX, "", "blockhash"},
            }
        },
        RPCExamples{
            "\nGenerate 11 blocks to mydesc\n" + HelpExampleCli("generatetodescriptor", "11 \"mydesc\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto num_blocks{self.Arg<int>("num_blocks")};
    const auto max_tries{self.Arg<uint64_t>("maxtries")};

    CScript coinbase_output_script;
    std::string error;
    if (!getScriptFromDescriptor(self.Arg<std::string>("descriptor"), coinbase_output_script, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    ChainstateManager& chainman = EnsureChainman(node);

    return generateBlocks(chainman, miner, coinbase_output_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generate()
{
    return RPCHelpMan{"generate", "has been replaced by the -generate cli option. Refer to -help for more information.", {}, {}, RPCExamples{""}, [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, self.ToString());
    }};
}

static RPCHelpMan generatetoaddress()
{
    return RPCHelpMan{"generatetoaddress",
        "Mine to a specified address and return the block hashes.",
         {
             {"nblocks", RPCArg::Type::NUM, RPCArg::Optional::NO, "How many blocks are generated."},
             {"address", RPCArg::Type::STR, RPCArg::Optional::NO, "The address to send the newly generated bitcoin to."},
             {"maxtries", RPCArg::Type::NUM, RPCArg::Default{DEFAULT_MAX_TRIES}, "How many iterations to try."},
         },
         RPCResult{
             RPCResult::Type::ARR, "", "hashes of blocks generated",
             {
                 {RPCResult::Type::STR_HEX, "", "blockhash"},
             }},
         RPCExamples{
            "\nGenerate 11 blocks to myaddress\n"
            + HelpExampleCli("generatetoaddress", "11 \"myaddress\"")
            + "If you are using the " CLIENT_NAME " wallet, you can get a new address to send the newly generated bitcoin to with:\n"
            + HelpExampleCli("getnewaddress", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const int num_blocks{request.params[0].getInt<int>()};
    const uint64_t max_tries{request.params[2].isNull() ? DEFAULT_MAX_TRIES : request.params[2].getInt<int>()};

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    ChainstateManager& chainman = EnsureChainman(node);

    CScript coinbase_output_script = GetScriptForDestination(destination);

    return generateBlocks(chainman, miner, coinbase_output_script, num_blocks, max_tries);
},
    };
}

static RPCHelpMan generateblock()
{
    return RPCHelpMan{"generateblock",
        "Mine a set of ordered transactions to a specified address or descriptor and return the block hash.",
        {
            {"output", RPCArg::Type::STR, RPCArg::Optional::NO, "The address or descriptor to send the newly generated bitcoin to."},
            {"transactions", RPCArg::Type::ARR, RPCArg::Optional::NO, "An array of hex strings which are either txids or raw transactions.\n"
                "Txids must reference transactions currently in the mempool.\n"
                "All transactions must be valid and in valid order, otherwise the block will be rejected.",
                {
                    {"rawtx/txid", RPCArg::Type::STR_HEX, RPCArg::Optional::OMITTED, ""},
                },
            },
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true}, "Whether to submit the block before the RPC call returns or to return it as hex."},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "",
            {
                {RPCResult::Type::STR_HEX, "hash", "hash of generated block"},
                {RPCResult::Type::STR_HEX, "hex", /*optional=*/true, "hex of generated block, only present when submit=false"},
            }
        },
        RPCExamples{
            "\nGenerate a block to myaddress, with txs rawtx and mempool_txid\n"
            + HelpExampleCli("generateblock", R"("myaddress" '["rawtx", "mempool_txid"]')")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    const auto address_or_descriptor = request.params[0].get_str();
    CScript coinbase_output_script;
    std::string error;

    if (!getScriptFromDescriptor(address_or_descriptor, coinbase_output_script, error)) {
        const auto destination = DecodeDestination(address_or_descriptor);
        if (!IsValidDestination(destination)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address or descriptor");
        }

        coinbase_output_script = GetScriptForDestination(destination);
    }

    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& miner = EnsureMining(node);
    const CTxMemPool& mempool = EnsureMemPool(node);

    std::vector<CTransactionRef> txs;
    const auto raw_txs_or_txids = request.params[1].get_array();
    for (size_t i = 0; i < raw_txs_or_txids.size(); i++) {
        const auto& str{raw_txs_or_txids[i].get_str()};

        CMutableTransaction mtx;
        if (auto hash{uint256::FromHex(str)}) {
            const auto tx{mempool.get(*hash)};
            if (!tx) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Transaction %s not in mempool.", str));
            }

            txs.emplace_back(tx);

        } else if (DecodeHexTx(mtx, str)) {
            txs.push_back(MakeTransactionRef(std::move(mtx)));

        } else {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Transaction decode failed for %s. Make sure the tx has at least one input.", str));
        }
    }

    const bool process_new_block{request.params[2].isNull() ? true : request.params[2].get_bool()};
    CBlock block;

    ChainstateManager& chainman = EnsureChainman(node);
    {
        LOCK(chainman.GetMutex());
        {
            std::unique_ptr<BlockTemplate> block_template{miner.createNewBlock({.use_mempool = false, .coinbase_output_script = coinbase_output_script})};
            CHECK_NONFATAL(block_template);

            block = block_template->getBlock();
        }

        CHECK_NONFATAL(block.vtx.size() == 1);

        // Add transactions
        block.vtx.insert(block.vtx.end(), txs.begin(), txs.end());
        RegenerateCommitments(block, chainman);

        // BTCA: Sign the block specifically for generateblock RPC
        block.vchBlockSignature.clear(); // Clear any signature from the template
        block.hashMerkleRoot = BlockMerkleRoot(block); // Calculate final Merkle Root

        const Consensus::Params& consensusParams = chainman.GetParams().GetConsensus();
        if (!consensusParams.designatedBlockProposerKeyID.IsNull()) {
            // For regtest, we'll use the hardcoded private key.
            // IMPORTANT: This is for regtest/testing ONLY. Real applications need secure key management.
            std::string strSecret = "cQStringQuSodyN8yL3v9S4qY1gB9dZsqFD27DbSCp2f1q4A2d8gX"; // Regtest WIF
            CKey privKey = DecodeSecret(strSecret);
            if (!privKey.IsValid()) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to decode private key for block signing in generateblock.");
            }
            // Ensure the derived public key matches the one in chainparams (optional sanity check)
            CPubKey pubKey = privKey.GetPubKey();
            if (pubKey.GetID() != consensusParams.designatedBlockProposerKeyID) {
                 throw JSONRPCError(RPC_INTERNAL_ERROR, "Private key does not correspond to designatedBlockProposerKeyID in generateblock.");
            }
            
            uint256 hashToSign = block.GetHashForSignature();
            if (!privKey.Sign(hashToSign, block.vchBlockSignature)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign block header in generateblock.");
            }
        }
        // BTCA: End of block signing for generateblock RPC

        BlockValidationState state;
        if (!TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock), /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
            throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("TestBlockValidity failed: %s", state.ToString()));
        }
    }

    std::shared_ptr<const CBlock> block_out;
    uint64_t max_tries{DEFAULT_MAX_TRIES};

    if (!GenerateBlock(chainman, std::move(block), max_tries, block_out, process_new_block) || !block_out) {
        throw JSONRPCError(RPC_MISC_ERROR, "Failed to make block.");
    }

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("hash", block_out->GetHash().GetHex());
    if (!process_new_block) {
        DataStream block_ser;
        block_ser << TX_WITH_WITNESS(*block_out);
        obj.pushKV("hex", HexStr(block_ser));
    }
    return obj;
},
    };
}

static RPCHelpMan getmininginfo()
{
    return RPCHelpMan{"getmininginfo",
                "\nReturns a json object containing mining-related information.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "currentblockweight", /*optional=*/true, "The block weight (including reserved weight for block header, txs count and coinbase tx) of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::NUM, "currentblocktx", /*optional=*/true, "The number of block transactions (excluding coinbase) of the last assembled block (only present if a block was ever assembled)"},
                        {RPCResult::Type::STR_HEX, "bits", "The current nBits, compact representation of the block difficulty target"},
                        {RPCResult::Type::NUM, "difficulty", "The current difficulty"},
                        {RPCResult::Type::STR_HEX, "target", "The current target"},
                        {RPCResult::Type::NUM, "networkhashps", "The network hashes per second"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                        {RPCResult::Type::STR_HEX, "signet_challenge", /*optional=*/true, "The block challenge (aka. block script), in hexadecimal (only present if the current network is a signet)"},
                        {RPCResult::Type::OBJ, "next", "The next block",
                        {
                            {RPCResult::Type::NUM, "height", "The next height"},
                            {RPCResult::Type::STR_HEX, "bits", "The next target nBits"},
                            {RPCResult::Type::NUM, "difficulty", "The next difficulty"},
                            {RPCResult::Type::STR_HEX, "target", "The next target"}
                        }},
                        (IsDeprecatedRPCEnabled("warnings") ?
                            RPCResult{RPCResult::Type::STR, "warnings", "any network and blockchain warnings (DEPRECATED)"} :
                            RPCResult{RPCResult::Type::ARR, "warnings", "any network and blockchain warnings (run with `-deprecatedrpc=warnings` to return the latest warning as a single string)",
                            {
                                {RPCResult::Type::STR, "", "warning"},
                            }
                            }
                        ),
                    }},
                RPCExamples{
                    HelpExampleCli("getmininginfo", "")
            + HelpExampleRpc("getmininginfo", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    NodeContext& node = EnsureAnyNodeContext(request.context);
    const CTxMemPool& mempool = EnsureMemPool(node);
    ChainstateManager& chainman = EnsureChainman(node);
    LOCK(cs_main);
    const CChain& active_chain = chainman.ActiveChain();
    CBlockIndex& tip{*CHECK_NONFATAL(active_chain.Tip())};

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("blocks",           active_chain.Height());
    if (BlockAssembler::m_last_block_weight) obj.pushKV("currentblockweight", *BlockAssembler::m_last_block_weight);
    if (BlockAssembler::m_last_block_num_txs) obj.pushKV("currentblocktx", *BlockAssembler::m_last_block_num_txs);
    obj.pushKV("bits", strprintf("%08x", tip.nBits));
    obj.pushKV("difficulty", GetDifficulty(tip));
    obj.pushKV("target", GetTarget(tip, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("networkhashps",    getnetworkhashps().HandleRequest(request));
    obj.pushKV("pooledtx",         (uint64_t)mempool.size());
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());

    UniValue next(UniValue::VOBJ);
    CBlockIndex next_index;
    NextEmptyBlockIndex(tip, chainman.GetConsensus(), next_index);

    next.pushKV("height", next_index.nHeight);
    next.pushKV("bits", strprintf("%08x", next_index.nBits));
    next.pushKV("difficulty", GetDifficulty(next_index));
    next.pushKV("target", GetTarget(next_index, chainman.GetConsensus().powLimit).GetHex());
    obj.pushKV("next", next);

    if (chainman.GetParams().GetChainType() == ChainType::SIGNET) {
        const std::vector<uint8_t>& signet_challenge =
            chainman.GetConsensus().signet_challenge;
        obj.pushKV("signet_challenge", HexStr(signet_challenge));
    }
    obj.pushKV("warnings", node::GetWarningsForRpc(*CHECK_NONFATAL(node.warnings), IsDeprecatedRPCEnabled("warnings")));
    return obj;
},
    };
}


// NOTE: Unlike wallet RPC (which use BTC values), mining RPCs follow GBT (BIP 22) in using satoshi amounts
static RPCHelpMan prioritisetransaction()
{
    return RPCHelpMan{"prioritisetransaction",
                "Accepts the transaction into mined blocks at a higher (or lower) priority\n",
                {
                    {"txid", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The transaction id."},
                    {"dummy", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "API-Compatibility for previous API. Must be zero or null.\n"
            "                  DEPRECATED. For forward compatibility use named arguments and omit this parameter."},
                    {"fee_delta", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee."},
                },
                RPCResult{
                    RPCResult::Type::BOOL, "", "Returns true"},
                RPCExamples{
                    HelpExampleCli("prioritisetransaction", "\"txid\" 0.0 10000")
            + HelpExampleRpc("prioritisetransaction", "\"txid\", 0.0, 10000")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    LOCK(cs_main);

    uint256 hash(ParseHashV(request.params[0], "txid"));
    const auto dummy{self.MaybeArg<double>("dummy")};
    CAmount nAmount = request.params[2].getInt<int64_t>();

    if (dummy && *dummy != 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.");
    }

    CTxMemPool& mempool = EnsureAnyMemPool(request.context);

    // Non-0 fee dust transactions are not allowed for entry, and modification not allowed afterwards
    const auto& tx = mempool.get(hash);
    if (mempool.m_opts.require_standard && tx && !GetDust(*tx, mempool.m_opts.dust_relay_feerate).empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Priority is not supported for transactions with dust outputs.");
    }

    mempool.PrioritiseTransaction(hash, nAmount);
    return true;
},
    };
}

static RPCHelpMan getprioritisedtransactions()
{
    return RPCHelpMan{"getprioritisedtransactions",
        "Returns a map of all user-created (see prioritisetransaction) fee deltas by txid, and whether the tx is present in mempool.",
        {},
        RPCResult{
            RPCResult::Type::OBJ_DYN, "", "prioritisation keyed by txid",
            {
                {RPCResult::Type::OBJ, "<transactionid>", "", {
                    {RPCResult::Type::NUM, "fee_delta", "transaction fee delta in satoshis"},
                    {RPCResult::Type::BOOL, "in_mempool", "whether this transaction is currently in mempool"},
                    {RPCResult::Type::NUM, "modified_fee", /*optional=*/true, "modified fee in satoshis. Only returned if in_mempool=true"},
                }}
            },
        },
        RPCExamples{
            HelpExampleCli("getprioritisedtransactions", "")
            + HelpExampleRpc("getprioritisedtransactions", "")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            NodeContext& node = EnsureAnyNodeContext(request.context);
            CTxMemPool& mempool = EnsureMemPool(node);
            UniValue rpc_result{UniValue::VOBJ};
            for (const auto& delta_info : mempool.GetPrioritisedTransactions()) {
                UniValue result_inner{UniValue::VOBJ};
                result_inner.pushKV("fee_delta", delta_info.delta);
                result_inner.pushKV("in_mempool", delta_info.in_mempool);
                if (delta_info.in_mempool) {
                    result_inner.pushKV("modified_fee", *delta_info.modified_fee);
                }
                rpc_result.pushKV(delta_info.txid.GetHex(), std::move(result_inner));
            }
            return rpc_result;
        },
    };
}


// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const BlockValidationState& state)
{
    if (state.IsValid())
        return UniValue::VNULL;

    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, state.ToString());
    if (state.IsInvalid())
    {
        std::string strRejectReason = state.GetRejectReason();
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

// Prefix rule name with ! if not optional, see BIP9
static std::string gbt_rule_value(const std::string& name, bool gbt_optional_rule)
{
    std::string s{name};
    if (!gbt_optional_rule) {
        s.insert(s.begin(), '!');
    }
    return s;
}

static RPCHelpMan getblocktemplate()
{
    return RPCHelpMan{"getblocktemplate",
                "\nIf the request parameters object is empty, returns the block template suitable for mining.\nIf parameters must be specified, it is better to use the named parameters manner correctly (see example below).\nAny information that pertains to the next block must be updated in this template.\nWARNING: Bitcoinall has Proof-of-Work disabled. This RPC is deprecated and will likely be removed or significantly changed in future versions.\n",
                {
                    {"template_request", RPCArg::Type::OBJ, RPCArg::Default{UniValue::VOBJ}, "Format of the template",
                        {
                            {"mode", RPCArg::Type::STR, RPCArg::Default{"template"}, "This must be set to \"template\", \"proposal\" (see BIP23), or \"dump\" (see BIP145)"},
                            {"rules", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A list of strings outlining client features",
                                {
                                    {"value", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported feature, 'segwit' and 'segwit-block' are automatically reported"},
                                },
                                "rules"
                            },
                            {"capabilities", RPCArg::Type::ARR, RPCArg::Default{UniValue::VARR}, "A list of strings giving client capabilities. Currently only 'proposal' is supported.",
                                {
                                    {"value", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "client side supported capability"},
                                },
                            },
                            {"longpollid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Previously seen longpollid indicates this call is a follow-up to a getblocktemplate call. Save hashrate estimate, and send an update if a new block is found"},
                        },
                        "template_request"
                    },
                },
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::ELISION, "", "Various keys from the JSON-RPC 2.0 specification are present here. Clear help for details."}
                    }
                },
                RPCExamples{
                    HelpExampleCli("getblocktemplate", "\"{\\\"rules\\\":[\\\"segwit\\\"]}\"")
                  + HelpExampleRpc("getblocktemplate", "{\"rules\":[\"segwit\"]}")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // BTCA: PoW is disabled.
    throw JSONRPCError(RPC_METHOD_DEPRECATED, "Proof-of-Work mining is disabled in Bitcoinall. getblocktemplate is deprecated.");
    // Todo el código original de la función ha sido eliminado/comentado.
    /*
    ChainstateManager& chainman = EnsureAnyChainman(request.context);
    NodeContext& node = EnsureAnyNodeContext(request.context);
    Mining& mining_interface = EnsureMining(node);

    LOCK(cs_main);

    // RPCArg comments are not used for argument description, RPCHelpMan does that.
    const UniValue& request_params = request.params[0].get_obj();

    // Options:
    // JSONRPCType mode = request_params["mode"].type();
    const std::string mode = request_params.exists("mode") ? request_params["mode"].get_str() : "template";

    if (mode == "dump") {
        DisconnectedBlockTransactions disconnected_pool{Assert(node.mempool)->GetDisconnectedPool()};
        disconnected_pool.DumpToDisk();
        return NullUniValue;
    }

    if (mode != "template" && mode != "proposal") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid mode");
    }

    if (chainman.IsInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Bitcoin is downloading blocks...");
    }

    // TODO: remove this when GBT clients have been updated to RPCAccount terms
    if (request.params[0].isObject()) {
        UniValue par = request.params["rules"].get_obj();
        RPCTypeCheckArgument(par["rules"], UniValue::VARR);
    }

    static const std::set<std::string> SUPPORTED_RULES{{
        "!segwit",
        "!blockversion", // Ignore bitcoind's version
        "!vbavailable",  // Ignore bitcoind's version bits
        "!norecursivemutation", // Ignore proposal requirement not to mutate parent
        "csv", // Require CoinBaseSoftfork block version for CSV
    }};

    // The features supported by this template.
    UniValue features(UniValue::VARR);
    features.push_back("segwit");
    features.push_back("segwit-block"); // Always allows segwit blocks, this client does not care what other clients support

    // Check for rule compatibility
    std::set<std::string> setClientRules;
    if (request_params.exists("rules") && request_params["rules"].isArray()) {
        const UniValue& arr = request_params["rules"].get_array();
        for (unsigned int i = 0; i < arr.size(); ++i) {
            const UniValue& val = arr[i];
            if (val.isStr()) {
                setClientRules.insert(val.get_str());
            }
        }
    }

    // Check for segwit rule compatibility. We require "segwit" or "!segwit" for this client version.
    // Note that the lack of "segwit" or presence of "!segwit" indicates the client can't produce segwit blocks.
    if (setClientRules.count("segwit") == 0 && setClientRules.count("!segwit") == 0) {
        // This error message comes from BIP9, SegWit an exception to "BiP9 requires that implementations ignore unknown rules".
        throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called with the segwit rule set (call with \"rules\":[\"segwit\"])");
    }

    std::unique_ptr<BlockTemplate> blocktemplate = mining_interface.getBlockTemplate(request_params, setClientRules);
    if (!blocktemplate) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Couldn't create new block");
    }

    if (mode == "proposal")
    {
        const CBlock& block = blocktemplate->getBlock();
        for (const auto& tx : block.vtx) {
            if (tx->IsCoinBase()) continue;
            for (const auto& txin : tx->vin) {
                const CTxMemPoolEntry* entry = Assert(node.mempool)->GetEntry(txin.prevout.hash);
                if (entry && entry->IsDirty()) {
                    throw JSONRPCError(RPC_VERIFY_ERROR, "Proposal targetting transaction with dirty dependencies");
                }
            }
        }

        const UniValue& data = request_params["data"];
        if (!data.isStr()) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Missing data String key for proposal");
        }

        CBlock block_proposal;
        if (!DecodeHexBlk(block_proposal, data.get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
        }

        const uint256 hash = block_proposal.GetHash();
        const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return "duplicate";
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                return "duplicate-invalid";
            }
            return "duplicate-inconclusive";
        }

        CBlockIndex* const pindexPrev = chainman.ActiveChain().Tip();
        // TestBlockValidity only supports blocks built on the current Tip
        if (block_proposal.hashPrevBlock != pindexPrev->GetBlockHash()) {
            return "inconclusive-not-best-prevblk";
        }
        BlockValidationState state;
        chainman.TestBlockValidity(state, block_proposal, pindexPrev, GetAdjustedTime(), false, true);
        return BIP22ValidationResult(state);
    }

    CBlock& block = blocktemplate->getBlock();
    const uint64_t nTxFees = blocktemplate->getTxFees();

    // Make sure this block will follow all rules sometimes skipped in TestBlockValidity such as BIP30
    if (chainman.ActiveChain().Tip()->nHeight + 1 >= Params().GetConsensus().BIP30Height) {
        const CCoinsViewCache view(&chainman.ActiveChainstate().CoinsTip());
        BlockValidationState state_check_contextual;
        if (!ContextualCheckBlock(block, state_check_contextual, view, Params().GetConsensus(), chainman.ActiveChain().Tip())) {
            // ContextualCheckBlock providing a useful error string is a work in progress
            throw JSONRPCError(RPC_VERIFY_ERROR, "Block violates fork specific rules (BIP30 or other). Please check the log.");
        }
    }

    // The following rules are checked first by the assembler but also checked here to ensure that the GBT result is valid according to the current state.
    // Particularly important when the chain tip may have changed mid-assembly, making a transaction no longer valid for the new tip.
    BlockValidationState state_final_check;
    if (!CheckBlock(block, state_final_check, Params().GetConsensus(), chainman.ActiveChainstate().Flags(), false, false)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Block does not pass final check. Please check the log.");
    }

    std::vector<std::string>rules_applied = blocktemplate->getRulesApplied();
    if (setClientRules.count("!segwit")) rules_applied.push_back("!segwit");
    rules_applied.push_back("csv");

    // Add explicitly requested rules to the result
    for (const std::string& rule : setClientRules) {
        // Add rules that are not part of SUPPORTED_RULES to the result, if they are not already.
        // This allows clients to signal support for softforks that are not listed in SUPPORTED_RULES.
        if (SUPPORTED_RULES.find(rule) == SUPPORTED_RULES.end() && std::find(rules_applied.begin(), rules_applied.end(), rule) == rules_applied.end()) {
            rules_applied.push_back(rule);
        }
    }

    UniValue result = GetBlockTemplateResult(chainman.ActiveChainstate(), chainman.GetConsensus(),
                                            block, nTxFees, rules_applied,
                                            blocktemplate->getVBRequired(), *Assert(node.mempool));
    result.pushKV("longpollid", chainman.ActiveChain().Tip()->GetBlockHash().ToString() + ToString(Assert(node.mempool)->GetTransactionsUpdated()));
    return result;
    */
},
    };
}

class submitblock_StateCatcher final : public CValidationInterface
{
public:
    uint256 hash;
    bool found{false};
    BlockValidationState state;

    explicit submitblock_StateCatcher(const uint256 &hashIn) : hash(hashIn), state() {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override {
        if (block.GetHash() != hash)
            return;
        found = true;
        state = stateIn;
    }
};

static RPCHelpMan submitblock()
{
    return RPCHelpMan{"submitblock",
                "\nAttempts to submit new block to network.\nSee https://en.bitcoin.it/wiki/BIP_0022 for full specification.\nWARNING: Bitcoinall has Proof-of-Work disabled. This RPC is deprecated and will likely be removed or significantly changed in future versions.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block data"},
                    {"dummy", RPCArg::Type::STR, RPCArg::Default{"ignored"}, "dummy value, for compatibility with BIP22. This argument is ignored."},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "Returns JSON Null when valid, a string according to BIP22 otherwise"},
                RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // BTCA: PoW is disabled.
    throw JSONRPCError(RPC_METHOD_DEPRECATED, "Proof-of-Work mining is disabled in Bitcoinall. submitblock is deprecated.");
    /*
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    bool new_block;
    submitblock_StateCatcher sc(hash);
    RegisterSharedValidationInterface(sc.GetWeak());
    bool accepted = chainman.ProcessNewBlock(blockptr, true, true, &new_block);
    UnregisterSharedValidationInterface(sc.GetWeak());
    node.validation_signals->SyncWithValidationInterfaceQueue();
    if (sc.found) {
        if (sc.state.IsInvalid()) {
            if (sc.state.GetResult() == BlockValidationResult::BLOCK_MUTATED) {
                return "mutated";
            }
            return "invalid";
        }
        if (accepted && new_block) {
            return NullUniValue;
        }
        return "duplicate";
    }
    if (accepted) {
        if (chainman.ActiveChain().Tip()->GetBlockHash() != hash && // Not the new tip ...
                chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock) == nullptr) { // ... and not an orphan
            // We accepted the block, but it is not the new tip, and it is not an orphan,
            // then it must be a reorg.
            return "accepted-still-old-tip";
        }
        return "accepted"; // This means we accepted the block, but it is an orphan.
    }
    // We didn't accept the block, we don't have a state for it, so we don't know why
    return "rejected";
    */
},
    };
}

static RPCHelpMan submitheader()
{
    return RPCHelpMan{"submitheader",
                "\nDecode hex-encoded block header and submit to network.\nWARNING: Bitcoinall has Proof-of-Work disabled. This RPC is deprecated and will likely be removed or significantly changed in future versions.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "the hex-encoded block header"},
                },
                RPCResult{
                    RPCResult::Type::NONE, "", "None on success"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"")
            + HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    // BTCA: PoW is disabled.
    throw JSONRPCError(RPC_METHOD_DEPRECATED, "Proof-of-Work mining is disabled in Bitcoinall. submitheader is deprecated.");
    /*
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);

    CBlockHeader h;
    if (!DecodeHexBlockHeader(h, request.params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block header decode failed");
    }
    BlockValidationState state;
    chainman.ProcessNewBlockHeaders({h}, state, Params(), nullptr);
    if (state.IsInvalid()) {
        std::string strError = "invalid header: " + state.ToString();
        throw JSONRPCError(RPC_VERIFY_ERROR, strError);
    }
    if (!chainman.ActiveChain().Contains(chainman.m_blockman.LookupBlockIndex(h.GetHash()))) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "header not accepted");
    }
    return NullUniValue;
    */
},
    };
}

void RegisterMiningRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"mining", &getnetworkhashps},
        {"mining", &getmininginfo},
        {"mining", &prioritisetransaction},
        {"mining", &getprioritisedtransactions},
        {"mining", &getblocktemplate},
        {"mining", &submitblock},
        {"mining", &submitheader},

        {"hidden", &generatetoaddress},
        {"hidden", &generatetodescriptor},
        {"hidden", &generateblock},
        {"hidden", &generate},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
