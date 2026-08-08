// Copyright (c) 2025-2026 The Bitcoin All developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NODE_POU_PEERS_H
#define BITCOIN_NODE_POU_PEERS_H

#include <key.h>
#include <net.h>

#include <cstdint>
#include <vector>

/** Record a PoU identity announced by a connected peer. */
void RegisterPouPeerAnnouncement(const CKeyID& key_id, NodeId node_id);

/** Remove PoU announcements tied to a disconnected peer. */
void RemovePouPeerAnnouncements(NodeId node_id);

/** Return KeyIDs announced by currently connected peers (excluding self). */
std::vector<CKeyID> ListAnnouncedPouPeerKeyIDs();

#endif // BITCOIN_NODE_POU_PEERS_H
