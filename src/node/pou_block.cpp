// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pou_block.h>

#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <interfaces/mining.h>
#include <node/miner.h>
#include <util/signalinterrupt.h>
#include <validation.h>

namespace {

bool ProcessPoUBlock(ChainstateManager& chainman, CBlock&& block, std::shared_ptr<const CBlock>& block_out)
{
    block_out.reset();
    block.hashMerkleRoot = BlockMerkleRoot(block);
    if (bool{chainman.m_interrupt}) return false;
    block_out = std::make_shared<const CBlock>(std::move(block));
    return chainman.ProcessNewBlock(block_out, /*force_processing=*/true, /*min_pow_checked=*/true, nullptr);
}

} // namespace

bool MineBlockIncludingPoUTx(ChainstateManager& chainman,
                             interfaces::Mining& miner,
                             const CTransactionRef& pou_tx,
                             const CScript& coinbase_output_script,
                             uint256& block_hash_out,
                             std::string& error_out)
{
    CBlock block;
    {
        LOCK(chainman.GetMutex());
        std::unique_ptr<interfaces::BlockTemplate> block_template{
            miner.createNewBlock({.use_mempool = false, .coinbase_output_script = coinbase_output_script})};
        if (!block_template) {
            error_out = "Failed to create block template";
            return false;
        }
        block = block_template->getBlock();
        block.vtx.push_back(pou_tx);
        node::RegenerateCommitments(block, chainman);
        block.vchBlockSignature.clear();
        block.hashMerkleRoot = BlockMerkleRoot(block);

        BlockValidationState state;
        if (!TestBlockValidity(state, chainman.GetParams(), chainman.ActiveChainstate(), block,
                               chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock),
                               /*fCheckPOW=*/false, /*fCheckMerkleRoot=*/false)) {
            error_out = strprintf("TestBlockValidity failed: %s", state.ToString());
            return false;
        }
    }

    std::shared_ptr<const CBlock> block_out;
    if (!ProcessPoUBlock(chainman, std::move(block), block_out) || !block_out) {
        error_out = "Failed to produce PoU block";
        return false;
    }
    block_hash_out = block_out->GetHash();
    return true;
}
