// Copyright (c) 2025 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_BTCA_UPTIME_H
#define BITCOIN_CONSENSUS_BTCA_UPTIME_H

class CCoinsViewCache;
class CTransaction;

/** Update PoU uptime state when a BTCA_TIME transaction is confirmed in a block. */
void ApplyBtcaUptimeFromTransaction(const CTransaction& tx, CCoinsViewCache& view);

#endif // BITCOIN_CONSENSUS_BTCA_UPTIME_H
