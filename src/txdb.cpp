// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txdb.h>

#include <coins.h>
#include <dbwrapper.h>
#include <logging.h>
#include <primitives/transaction.h>
#include <random.h>
#include <serialize.h>
#include <uint256.h>
#include <util/vector.h>

#include <cassert>
#include <cstdlib>
#include <iterator>
#include <utility>

static constexpr uint8_t DB_COIN{'C'};
static constexpr uint8_t DB_BEST_BLOCK{'B'};
static constexpr uint8_t DB_HEAD_BLOCKS{'H'};
// Keys used in previous version that might still be found in the DB:
static constexpr uint8_t DB_COINS{'c'};

bool CCoinsViewDB::NeedsUpgrade()
{
    std::unique_ptr<CDBIterator> cursor{m_db->NewIterator()};
    // DB_COINS was deprecated in v0.15.0, commit
    // 1088b02f0ccd7358d2b7076bb9e122d59d502d02
    cursor->Seek(std::make_pair(DB_COINS, uint256{}));
    return cursor->Valid();
}

namespace {

struct CoinEntry {
    COutPoint* outpoint;
    uint8_t key;
    explicit CoinEntry(const COutPoint* ptr) : outpoint(const_cast<COutPoint*>(ptr)), key(DB_COIN)  {}

    SERIALIZE_METHODS(CoinEntry, obj) { READWRITE(obj.key, obj.outpoint->hash, VARINT(obj.outpoint->n)); }
};

} // namespace

CCoinsViewDB::CCoinsViewDB(DBParams db_params, CoinsViewOptions options) :
    m_db_params{std::move(db_params)},
    m_options{std::move(options)},
    m_db{std::make_unique<CDBWrapper>(m_db_params)} { }

void CCoinsViewDB::ResizeCache(size_t new_cache_size)
{
    // We can't do this operation with an in-memory DB since we'll lose all the coins upon
    // reset.
    if (!m_db_params.memory_only) {
        // Have to do a reset first to get the original `m_db` state to release its
        // filesystem lock.
        m_db.reset();
        m_db_params.cache_bytes = new_cache_size;
        m_db_params.wipe_data = false;
        m_db = std::make_unique<CDBWrapper>(m_db_params);
    }
}

std::optional<Coin> CCoinsViewDB::GetCoin(const COutPoint& outpoint) const
{
    if (Coin coin; m_db->Read(CoinEntry(&outpoint), coin)) return coin;
    return std::nullopt;
}

bool CCoinsViewDB::HaveCoin(const COutPoint &outpoint) const {
    return m_db->Exists(CoinEntry(&outpoint));
}

uint256 CCoinsViewDB::GetBestBlock() const {
    uint256 hashBestChain;
    if (!m_db->Read(DB_BEST_BLOCK, hashBestChain))
        return uint256();
    return hashBestChain;
}

std::vector<uint256> CCoinsViewDB::GetHeadBlocks() const {
    std::vector<uint256> vhashHeadBlocks;
    if (!m_db->Read(DB_HEAD_BLOCKS, vhashHeadBlocks)) {
        return std::vector<uint256>();
    }
    return vhashHeadBlocks;
}

bool CCoinsViewDB::GetUptime(const CKeyID& keyID, uint64_t& nUptime) const {
    return m_db->Read(std::make_pair(DB_UPTIME, keyID), nUptime);
}

bool CCoinsViewDB::GetLastRewardedUptime(const CKeyID& keyID, uint64_t& nLastRewardedUptime) const {
    return m_db->Read(std::make_pair(DB_LAST_REWARDED_UPTIME, keyID), nLastRewardedUptime);
}

bool CCoinsViewDB::BatchWrite(CoinsViewCacheCursor& cursor, const uint256 &hashBlock) {
    CDBBatch batch(*m_db);
    size_t count = 0;
    size_t changed = 0;
    assert(!hashBlock.IsNull());

    uint256 old_tip = GetBestBlock();
    if (old_tip.IsNull()) {
        // We may be in the middle of replaying.
        std::vector<uint256> old_heads = GetHeadBlocks();
        if (old_heads.size() == 2) {
            if (old_heads[0] != hashBlock) {
                LogPrintLevel(BCLog::COINDB, BCLog::Level::Error, "The coins database detected an inconsistent state, likely due to a previous crash or shutdown. You will need to restart bitcoind with the -reindex-chainstate or -reindex configuration option.\n");
            }
            assert(old_heads[0] == hashBlock);
            old_tip = old_heads[1];
        }
    }

    // In the first batch, mark the database as being in the middle of a
    // transition from old_tip to hashBlock.
    // A vector is used for future extensibility, as we may want to support
    // interrupting after partial writes from multiple independent reorgs.
    batch.Erase(DB_BEST_BLOCK);
    batch.Write(DB_HEAD_BLOCKS, Vector(hashBlock, old_tip));

    for (auto it{cursor.Begin()}; it != cursor.End();) {
        if (it->second.IsDirty()) {
            CoinEntry entry(&it->first);
            if (it->second.coin.IsSpent()) {
                batch.Erase(entry);
            } else {
                batch.Write(entry, it->second.coin);
            }

            changed++;
        }
        count++;
        it = cursor.NextAndMaybeErase(*it);
        if (batch.ApproximateSize() > m_options.batch_write_bytes) {
            LogDebug(BCLog::COINDB, "Writing partial batch of %.2f MiB\n", batch.ApproximateSize() * (1.0 / 1048576.0));

            m_db->WriteBatch(batch);
            batch.Clear();
            if (m_options.simulate_crash_ratio) {
                static FastRandomContext rng;
                if (rng.randrange(m_options.simulate_crash_ratio) == 0) {
                    LogPrintf("Simulating a crash. Goodbye.\n");
                    _Exit(0);
                }
            }
        }
    }

    // In the last batch, mark the database as consistent with hashBlock again.
    batch.Erase(DB_HEAD_BLOCKS);
    batch.Write(DB_BEST_BLOCK, hashBlock);

    // BTCA: Add uptime data to batch
    for (const auto& entry : cursor.m_write_uptime) {
        batch.Write(std::make_pair(DB_UPTIME, entry.first), entry.second);
        changed++; // Consider this a change
    }
    for (const auto& entry : cursor.m_write_last_rewarded_uptime) {
        batch.Write(std::make_pair(DB_LAST_REWARDED_UPTIME, entry.first), entry.second);
        changed++; // Consider this a change
    }
    for (const auto& key_to_delete : cursor.m_delete_uptime) {
        batch.Erase(std::make_pair(DB_UPTIME, key_to_delete));
        changed++; // Consider this a change
    }
    for (const auto& key_to_delete : cursor.m_delete_last_rewarded_uptime) {
        batch.Erase(std::make_pair(DB_LAST_REWARDED_UPTIME, key_to_delete));
        changed++; // Consider this a change
    }
    // Clear the write/delete maps in the cursor after processing
    cursor.m_write_uptime.clear();
    cursor.m_write_last_rewarded_uptime.clear();
    cursor.m_delete_uptime.clear();
    cursor.m_delete_last_rewarded_uptime.clear();

    LogDebug(BCLog::COINDB, "Writing final batch of %.2f MiB\n", batch.ApproximateSize() * (1.0 / 1048576.0));
    bool ret = m_db->WriteBatch(batch);
    LogDebug(BCLog::COINDB, "Committed %u changed transaction outputs (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return ret;
}

size_t CCoinsViewDB::EstimateSize() const
{
    return m_db->EstimateSize(DB_COIN, uint8_t(DB_COIN + 1));
}

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    // Prefer using CCoinsViewDB::Cursor() since we want to perform some
    // cache warmup on instantiation.
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256&hashBlockIn):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    ~CCoinsViewDBCursor() = default;

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;

    bool Valid() const override;
    void Next() override;

private:
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;
};

std::unique_ptr<CCoinsViewCursor> CCoinsViewDB::Cursor() const
{
    auto i = std::make_unique<CCoinsViewDBCursor>(
        const_cast<CDBWrapper&>(*m_db).NewIterator(), GetBestBlock());
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    i->pcursor->Seek(DB_COIN);
    // Cache key of first record
    if (i->pcursor->Valid()) {
        CoinEntry entry(&i->keyTmp.second);
        i->pcursor->GetKey(entry);
        i->keyTmp.first = entry.key;
    } else {
        i->keyTmp.first = 0; // Make sure Valid() and GetKey() return false
    }
    return i;
}

bool CCoinsViewDBCursor::GetKey(COutPoint &key) const
{
    // Return cached key
    if (keyTmp.first == DB_COIN) {
        key = keyTmp.second;
        return true;
    }
    return false;
}

bool CCoinsViewDBCursor::GetValue(Coin &coin) const
{
    return pcursor->GetValue(coin);
}

bool CCoinsViewDBCursor::Valid() const
{
    // Uncached key, return true if valid
    return keyTmp.first == DB_COIN && pcursor->Valid();
}

void CCoinsViewDBCursor::Next()
{
    // Bye bye old cached key
    keyTmp.first = 0;
    // Next entry
    pcursor->Next();
    if (Valid() && pcursor->Valid()) {
        // Cache key
        CoinEntry entry(&keyTmp.second);
        pcursor->GetKey(entry);
        keyTmp.first = entry.key;
    }
}

bool CoinsViewCache::Flush(size_t max_flush_size, bool flush_children)
{
    LOCK(cs_main);
    if (!m_base) return false;

    CoinsViewCacheCursor cache_cursor;
    cache_cursor.m_hash_block = m_hash_block;
    size_t cache_coins_size = 0;
    {
        for (auto it = m_cache_coins.begin(); it != m_cache_coins.end();) {
            if (it->second.IsDirty()) {
                cache_cursor.GetMap()[it->first] = it->second;
                cache_coins_size += it->second.coin.DynamicMemoryUsage();
            }
            // Prefetch PUNCTORs and then erase.
            // See https://github.com/bitcoin/bitcoin/pull/14242#discussion_r257197206 why.
            it = m_cache_coins.erase(it);

            if (max_flush_size > 0 && cache_coins_size >= max_flush_size) break;
        }
    }

    // BTCA: Add uptime data to cache_cursor for BatchWrite
    {
        LOCK(m_uptime_mutex);
        for (const auto& entry : m_cache_uptime) {
            // Only write if not marked for deletion.
            // The SetUptime method ensures that if an entry is in m_cache_uptime, it's not marked for deletion.
            cache_cursor.m_write_uptime[entry.first] = entry.second;
        }
        m_cache_uptime.clear();

        for (const auto& entry : m_cache_last_rewarded_uptime) {
            cache_cursor.m_write_last_rewarded_uptime[entry.first] = entry.second;
        }
        m_cache_last_rewarded_uptime.clear();

        for (const auto& entry : m_cache_uptime_delete) {
            if (entry.second) { // If marked for deletion (value is true)
                // Ensure we don't try to write and delete the same key in one batch if it was re-added
                if (cache_cursor.m_write_uptime.find(entry.first) == cache_cursor.m_write_uptime.end()) {
                    cache_cursor.m_delete_uptime.push_back(entry.first);
                }
            }
        }
        m_cache_uptime_delete.clear();

        for (const auto& entry : m_cache_last_rewarded_uptime_delete) {
            if (entry.second) { // If marked for deletion (value is true)
                if (cache_cursor.m_write_last_rewarded_uptime.find(entry.first) == cache_cursor.m_write_last_rewarded_uptime.end()) {
                    cache_cursor.m_delete_last_rewarded_uptime.push_back(entry.first);
                }
            }
        }
        m_cache_last_rewarded_uptime_delete.clear();
    }
    // END BTCA

    if (!m_base->BatchWrite(cache_cursor, m_hash_block)) {
        return false;
    }
    m_hash_block = uint256(); // TODO: replace with std::optional
    return true;
}

// BTCA: Implementations for connection time state in CoinsViewCache
bool CoinsViewCache::GetUptime(const CKeyID& keyID, uint64_t& nUptime) const {
    LOCK(m_uptime_mutex);
    auto del_it = m_cache_uptime_delete.find(keyID);
    if (del_it != m_cache_uptime_delete.end() && del_it->second) {
        return false; // Marked as deleted in cache
    }

    auto it = m_cache_uptime.find(keyID);
    if (it != m_cache_uptime.end()) {
        nUptime = it->second;
        return true;
    }
    // Not in cache or explicitly deleted, try base
    if (!m_base) return false; // Should not happen if Disconnect() not called
    return m_base->GetUptime(keyID, nUptime);
}

bool CoinsViewCache::GetLastRewardedUptime(const CKeyID& keyID, uint64_t& nLastRewardedUptime) const {
    LOCK(m_uptime_mutex);
    auto del_it = m_cache_last_rewarded_uptime_delete.find(keyID);
    if (del_it != m_cache_last_rewarded_uptime_delete.end() && del_it->second) {
        return false; // Marked as deleted in cache
    }

    auto it = m_cache_last_rewarded_uptime.find(keyID);
    if (it != m_cache_last_rewarded_uptime.end()) {
        nLastRewardedUptime = it->second;
        return true;
    }
    // Not in cache or explicitly deleted, try base
    if (!m_base) return false; // Should not happen if Disconnect() not called
    return m_base->GetLastRewardedUptime(keyID, nLastRewardedUptime);
}

void CoinsViewCache::SetUptime(const CKeyID& keyID, uint64_t nUptime) {
    LOCK(m_uptime_mutex);
    m_cache_uptime[keyID] = nUptime;
    m_cache_uptime_delete.erase(keyID); // Clear deletion flag if it was set
}

void CoinsViewCache::SetLastRewardedUptime(const CKeyID& keyID, uint64_t nLastRewardedUptime) {
    LOCK(m_uptime_mutex);
    m_cache_last_rewarded_uptime[keyID] = nLastRewardedUptime;
    m_cache_last_rewarded_uptime_delete.erase(keyID); // Clear deletion flag if it was set
}

void CoinsViewCache::DeleteUptime(const CKeyID& keyID) {
    LOCK(m_uptime_mutex);
    m_cache_uptime.erase(keyID); // Remove from values cache
    m_cache_uptime_delete[keyID] = true; // Mark as deleted
}

void CoinsViewCache::DeleteLastRewardedUptime(const CKeyID& keyID) {
    LOCK(m_uptime_mutex);
    m_cache_last_rewarded_uptime.erase(keyID); // Remove from values cache
    m_cache_last_rewarded_uptime_delete[keyID] = true; // Mark as deleted
}
// END BTCA

void CoinsViewCache::RemoveCoins(CCoinsView* view, const CTransaction& tx, unsigned int flags, CoinsViewCache* inputs)
{
// ... existing code ...
