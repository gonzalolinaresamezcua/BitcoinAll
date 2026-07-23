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
using node::SignBlockWithDesignatedProposer;
using node::UpdateTime;
using util::ToString;

static void EnsureLocalBlockGenerationAllowed(const CChainParams& params)
{
    if (!params.MineBlocksOnDemand()) {
        throw JSONRPCError(RPC_METHOD_DEPRECATED,
            "BitcoinAll nodes are validation-only and do not mine (Ethereum-style compatible node). "
            "Local block generation is available only on regtest.");
    }
}

/**
 * Return average network hashes per second based on the last 'lookup' blocks,
 * or from the last difficulty change if 'lookup' is -1.
 * If 'height' is -1, compute the estimate from current chain tip.
 * If 'height' is a valid block height, compute the estimate at the time when a given block was found.
 */
[[maybe_unused]] static UniValue GetNetworkHashPS(int lookup, int height, const CChain& active_chain) {
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
                "\nDEPRECATED for BitcoinAll: PoW mining is disabled. Always returns 0.\n"
                "Kept for RPC compatibility with Bitcoin Core clients.\n",
                {
                    {"nblocks", RPCArg::Type::NUM, RPCArg::Default{120}, "Ignored. Kept for compatibility."},
                    {"height", RPCArg::Type::NUM, RPCArg::Default{-1}, "Ignored. Kept for compatibility."},
                },
                RPCResult{
                    RPCResult::Type::NUM, "", "Always 0 (PoW mining disabled)"},
                RPCExamples{
                    HelpExampleCli("getnetworkhashps", "")
            + HelpExampleRpc("getnetworkhashps", "")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    return 0;
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
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    EnsureLocalBlockGenerationAllowed(chainman.GetParams());

    const auto num_blocks{self.Arg<int>("num_blocks")};
    const auto max_tries{self.Arg<uint64_t>("maxtries")};

    CScript coinbase_output_script;
    std::string error;
    if (!getScriptFromDescriptor(self.Arg<std::string>("descriptor"), coinbase_output_script, error)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    }

    Mining& miner = EnsureMining(node);

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
        "Mine to a specified address and return the block hashes.\n"
        "BTCA: Only available on regtest. Production nodes are validation-only (no mining).",
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
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    EnsureLocalBlockGenerationAllowed(chainman.GetParams());

    const int num_blocks{request.params[0].getInt<int>()};
    const uint64_t max_tries{request.params[2].isNull() ? DEFAULT_MAX_TRIES : request.params[2].getInt<int>()};

    CTxDestination destination = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destination)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Error: Invalid address");
    }

    Mining& miner = EnsureMining(node);

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
    NodeContext& node = EnsureAnyNodeContext(request.context);
    ChainstateManager& chainman = EnsureChainman(node);
    EnsureLocalBlockGenerationAllowed(chainman.GetParams());

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

        // BTCA: Re-sign after regenerating commitments (regtest only).
        block.hashMerkleRoot = BlockMerkleRoot(block);
        if (!SignBlockWithDesignatedProposer(block, chainman.GetParams().GetConsensus(), /*allow_embedded_key=*/true)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign block with designated proposer key.");
        }

        BlockValidationState state;
        if (!TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block, chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock), /*fCheckPOW=*/true, /*fCheckMerkleRoot=*/false)) {
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
                "\nReturns a json object describing BitcoinAll's non-mining (validation-only) node status.\n"
                "PoW mining is disabled; blocks are authenticated by a designated proposer signature.",
                {},
                RPCResult{
                    RPCResult::Type::OBJ, "", "",
                    {
                        {RPCResult::Type::BOOL, "mining", "Always false: BitcoinAll nodes do not mine"},
                        {RPCResult::Type::STR, "proof", "Consensus proof type (designated-proposer)"},
                        {RPCResult::Type::BOOL, "generate_allowed", "Whether local generate* RPCs are available (regtest only)"},
                        {RPCResult::Type::STR_HEX, "designated_proposer", /*optional=*/true, "Compressed pubkey of the designated block proposer"},
                        {RPCResult::Type::NUM, "blocks", "The current block"},
                        {RPCResult::Type::NUM, "pooledtx", "The size of the mempool"},
                        {RPCResult::Type::STR, "chain", "current network name (" LIST_CHAIN_NAMES ")"},
                        {RPCResult::Type::NUM, "networkhashps", "Always 0 (PoW disabled; kept for compatibility)"},
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

    UniValue obj(UniValue::VOBJ);
    obj.pushKV("mining", false);
    obj.pushKV("proof", "designated-proposer");
    obj.pushKV("generate_allowed", chainman.GetParams().MineBlocksOnDemand());
    const CPubKey& proposer{chainman.GetConsensus().designatedBlockProposerPubKey};
    if (proposer.IsValid()) {
        obj.pushKV("designated_proposer", HexStr(proposer));
    }
    obj.pushKV("blocks", active_chain.Height());
    obj.pushKV("pooledtx", (uint64_t)mempool.size());
    obj.pushKV("chain", chainman.GetParams().GetChainTypeString());
    obj.pushKV("networkhashps", 0);
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


static RPCHelpMan getblocktemplate()
{
    return RPCHelpMan{"getblocktemplate",
                "DISABLED: BitcoinAll nodes are validation-only and do not mine (Ethereum-style compatible node).\n",
                {
                    {"template_request", RPCArg::Type::STR, RPCArg::Default{""}, "Ignored. Kept for RPC compatibility."},
                },
                RPCResult{RPCResult::Type::NONE, "", "Always errors; mining is disabled"},
                RPCExamples{
                    HelpExampleCli("getblocktemplate", "\"{\\\"rules\\\":[\\\"segwit\\\"]}\"")
                  + HelpExampleRpc("getblocktemplate", "{\"rules\":[\"segwit\"]}")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    throw JSONRPCError(RPC_METHOD_DEPRECATED,
        "BitcoinAll nodes are validation-only and do not mine. getblocktemplate is disabled.");
},
    };
}

static RPCHelpMan submitblock()
{
    return RPCHelpMan{"submitblock",
                "DISABLED: BitcoinAll nodes are validation-only and do not mine.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Ignored. Kept for compatibility."},
                    {"dummy", RPCArg::Type::STR, RPCArg::Default{"ignored"}, "Ignored. Kept for BIP22 compatibility."},
                },
                RPCResult{RPCResult::Type::NONE, "", "Always errors; mining is disabled"},
                RPCExamples{
                    HelpExampleCli("submitblock", "\"mydata\"")
            + HelpExampleRpc("submitblock", "\"mydata\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    throw JSONRPCError(RPC_METHOD_DEPRECATED,
        "BitcoinAll nodes are validation-only and do not mine. submitblock is disabled.");
},
    };
}

static RPCHelpMan submitheader()
{
    return RPCHelpMan{"submitheader",
                "DISABLED: BitcoinAll nodes are validation-only and do not mine.\n",
                {
                    {"hexdata", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Ignored. Kept for compatibility."},
                },
                RPCResult{RPCResult::Type::NONE, "", "Always errors; mining is disabled"},
                RPCExamples{
                    HelpExampleCli("submitheader", "\"aabbcc\"")
            + HelpExampleRpc("submitheader", "\"aabbcc\"")
                },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
{
    throw JSONRPCError(RPC_METHOD_DEPRECATED,
        "BitcoinAll nodes are validation-only and do not mine. submitheader is disabled.");
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
