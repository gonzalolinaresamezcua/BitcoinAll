// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/pou_peers.h>

#include <sync.h>
#include <util/bitcoin_time.h>

#include <map>

namespace {

struct PouPeerRecord {
    NodeId node_id;
    int64_t last_seen;
};

Mutex g_pou_peers_mutex;
std::map<CKeyID, PouPeerRecord> g_pou_announced_peers GUARDED_BY(g_pou_peers_mutex);

} // namespace

void RegisterPouPeerAnnouncement(const CKeyID& key_id, NodeId node_id)
{
    LOCK(g_pou_peers_mutex);
    g_pou_announced_peers[key_id] = PouPeerRecord{node_id, GetTime()};
}

void RemovePouPeerAnnouncements(NodeId node_id)
{
    LOCK(g_pou_peers_mutex);
    for (auto it = g_pou_announced_peers.begin(); it != g_pou_announced_peers.end(); ) {
        if (it->second.node_id == node_id) {
            it = g_pou_announced_peers.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<CKeyID> ListAnnouncedPouPeerKeyIDs()
{
    LOCK(g_pou_peers_mutex);
    std::vector<CKeyID> result;
    result.reserve(g_pou_announced_peers.size());
    for (const auto& [key_id, record] : g_pou_announced_peers) {
        (void)record;
        result.push_back(key_id);
    }
    return result;
}
