// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    // PoW no se usa, devuelve siempre el límite (dificultad mínima)
    return UintToArith256(params.powLimit).GetCompact();
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    // PoW no se usa, devuelve siempre el límite (dificultad mínima)
    // Los parámetros pindexLast y nFirstBlockTime ya no son necesarios.
    return UintToArith256(params.powLimit).GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    // PoW no se usa, cualquier transición es permitida.
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (hash.data()[31] & 0x80) == 0; // Mantener por si se usa en fuzzing no relacionado a PoW
    return CheckProofOfWorkImpl(hash, nBits, params);
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    // PoW no se usa, pero si se llama, devuelve el límite.
    // La validez de nBits ya no se comprueba contra el objetivo PoW.
    // Simplemente se convierte pow_limit a arith_uint256.
    // Nota: Si nBits se sigue usando para algo más, esto podría necesitar ajuste.
    // Por ahora, asumimos que su único propósito era derivar el objetivo PoW.
    arith_uint256 target;
    target.SetCompact(UintToArith256(pow_limit).GetCompact()); // Devuelve el límite como objetivo.
    // Comprobaciones originales de fNegative, fOverflow, bnTarget == 0 se omiten
    // ya que estamos devolviendo un valor constante derivado de pow_limit.
    // Si pow_limit fuera inválido para SetCompact, se manejaría allí.
    return target;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    // PoW no se usa, siempre retorna true.
    // Los parámetros hash, nBits y params.powLimit ya no se usan aquí.
    return true;
}
