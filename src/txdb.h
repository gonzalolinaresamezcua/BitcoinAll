// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Copyright (c) 2025 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h> // Defines CCoinsView (interface), CCoinsMap, CCoinsViewCursor, CoinsViewCacheCursor (struct)
#include <dbwrapper.h>
#include <kernel/cs_main.h>
#include <key_io.h> // For CKeyID
#include <sync.h>
#include <util/fs.h>

#include <cstddef>
#include <cstdint>
#include <map> // For std::map
#include <memory>
#include <optional>
#include <vector>

// Forward declarations for types defined elsewhere (if not fully included)
class COutPoint; // Defined in primitives/outpoint.h, usually included via other headers like transaction.h then coins.h
class uint256;   // Defined in uint256.h, usually included via other headers

// BTCA: Database prefixes for connection time tracking
static const char DB_UPTIME = 'u';
static const char DB_LAST_REWARDED_UPTIME = 'l';

//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 16 << 20;

//! User-controlled performance and debug options.
struct CoinsViewOptions {
    //! Maximum database write batch size in bytes.
    size_t batch_write_bytes = nDefaultDbBatchSize;
    //! If non-zero, randomly exit when the database is flushed with (1/ratio)
    //! probability.
    int simulate_crash_ratio = 0;
};

// CCoinsView is defined in coins.h
// CoinsViewCacheCursor (struct) is defined in coins.h

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB final : public CCoinsView // CCoinsView is the interface from coins.h
{
protected:
    DBParams m_db_params;
    CoinsViewOptions m_options;
    std::unique_ptr<CDBWrapper> m_db;
public:
    explicit CCoinsViewDB(DBParams db_params, CoinsViewOptions options);

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) override; // CoinsViewCacheCursor is the struct from coins.h
    std::unique_ptr<CCoinsViewCursor> Cursor() const override; // CCoinsViewCursor is the class from coins.h

    // BTCA: Implementations for uptime, overriding pure virtuals from CCoinsView
    bool GetUptime(const CKeyID& keyID, uint64_t& nUptime) const override;
    bool GetLastRewardedUptime(const CKeyID& keyID, uint64_t& nLastRewardedUptime) const override;

    bool NeedsUpgrade();
    size_t EstimateSize() const override;
    void ResizeCache(size_t new_cache_size) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    std::optional<fs::path> StoragePath() { return m_db->StoragePath(); }
};

/**
 * A CoinsViewCache instance is a CCoinsView that adds a memory cache for data that is
 * frequently accessed. The cache is committed to the CCoinsViewDB by calling the
 * Flush() method. The CoinsViewCache is a base class that can be extended with behavior specific
 * to the caller, for example, by CCoinsViewErrorCatcher, which catches exceptions from the
 * CCoinsViewDB and converts them to error codes.
 */
class CoinsViewCache : public CCoinsView // This should inherit from CCoinsView (interface from coins.h)
{
public:
    CoinsViewCache(CCoinsView* base);
    CoinsViewCache(const CoinsViewCache&) = delete;
    CoinsViewCache& operator=(const CoinsViewCache&) = delete;

    std::optional<Coin> GetCoin(const COutPoint& outpoint) const override;
    bool HaveCoin(const COutPoint& outpoint) const override;
    uint256 GetBestBlock() const override;
    void SetBestBlock(const uint256 &hashBlock);
    bool BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) override; // CoinsViewCacheCursor is the struct from coins.h
    std::unique_ptr<CCoinsViewCursor> Cursor() const override; // CCoinsViewCursor is the class from coins.h
    size_t EstimateSize() const override;

    bool Flush(size_t max_flush_size = 0, bool flush_children = false);
    void RemoveCoins(CCoinsView* view, const CTransaction& tx, unsigned int flags, CoinsViewCache* inputs); // Takes another CoinsViewCache
    void Disconnect() { m_base = nullptr; }
    size_t GetCacheSize() const;
    size_t DynamicMemoryUsage() const;
    CCoinsMap& GetCacheMap() { return m_cache_coins; } // CCoinsMap from coins.h
    const CCoinsMap& GetCacheMap() const { return m_cache_coins; } // CCoinsMap from coins.h
    static void BatchWriteHelp(CDBBatch& batch, const uint256& hashBlock, const CCoinsMap& mapCoins, const bool erase = false); // CCoinsMap from coins.h

    // BTCA: Getters for connection time state, checking cache first, then base.
    bool GetUptime(const CKeyID& keyID, uint64_t& nUptime) const override;
    bool GetLastRewardedUptime(const CKeyID& keyID, uint64_t& nLastRewardedUptime) const override;

    // BTCA: Setters for connection time state (modifies cache only).
    void SetUptime(const CKeyID& keyID, uint64_t nUptime);
    void SetLastRewardedUptime(const CKeyID& keyID, uint64_t nLastRewardedUptime);
    void DeleteUptime(const CKeyID& keyID);
    void DeleteLastRewardedUptime(const CKeyID& keyID);

protected:
    CCoinsView* m_base GUARDED_BY(cs_main);
    CCoinsMap m_cache_coins GUARDED_BY(cs_main); // CCoinsMap from coins.h

    // BTCA: Cached connection time states.
    mutable Mutex m_uptime_mutex;
    std::map<CKeyID, uint64_t> m_cache_uptime GUARDED_BY(m_uptime_mutex);
    std::map<CKeyID, uint64_t> m_cache_last_rewarded_uptime GUARDED_BY(m_uptime_mutex);
    std::map<CKeyID, bool> m_cache_uptime_delete GUARDED_BY(m_uptime_mutex); // True if deleted
    std::map<CKeyID, bool> m_cache_last_rewarded_uptime_delete GUARDED_BY(m_uptime_mutex); // True if deleted

    uint256 m_hash_block GUARDED_BY(cs_main);
};

#endif // BITCOIN_TXDB_H