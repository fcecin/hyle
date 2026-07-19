#pragma once

#include <hyle/core/crypto.h>
#include <hyle/morphe/frame.h>
#include <hyle/services/transport.h>

#include <cstdint>
#include <map>
#include <set>
#include <vector>

namespace hyle::morphe {
using namespace hyle::services;

struct SimMeshPort;

struct SimMesh {
  std::vector<PubKey> members;
  std::map<PubKey, std::set<PubKey>> links;
  std::map<PubKey, SimMeshPort*> ports;
  std::map<PubKey, SeenCache> seen;
  uint32_t loss_pct = 0;
  uint64_t rng = 0x9E3779B97F4A7C15ull;
  uint64_t relay_count = 0, dropped_no_relay = 0, seen_drop = 0, delivered = 0, lost = 0;

  void init(const std::vector<PubKey>& mem) {
    members = mem;
    for (const auto& a : mem)
      for (const auto& b : mem)
        if (!(a == b)) links[a].insert(b);
  }
  bool linked(const PubKey& a, const PubKey& b) const {
    auto it = links.find(a);
    return it != links.end() && it->second.count(b) != 0;
  }
  void down(const PubKey& a, const PubKey& b) { links[a].erase(b); links[b].erase(a); }
  void up(const PubKey& a, const PubKey& b) { links[a].insert(b); links[b].insert(a); }

  uint32_t next() {
    rng += 0x9E3779B97F4A7C15ull;
    uint64_t z = rng;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return static_cast<uint32_t>((z ^ (z >> 31)) % 100);
  }
  bool loss() { return loss_pct != 0 && next() < loss_pct; }

  void deliver(const PubKey& to, const PubKey& from, MsgType type, wire::View payload, const MsgId& id);
  void route(const PubKey& from, const PubKey& to, MsgType type, wire::View payload);
  void broadcast(const PubKey& from, MsgType type, wire::View payload) {
    for (const auto& m : members)
      if (!(m == from)) route(from, m, type, payload);
  }
};

struct SimMeshPort : Transport {
  SimMesh* mesh;
  PubKey self;
  SimMeshPort(SimMesh* m, PubKey s) : mesh(m), self(s) { mesh->ports[self] = this; }
  void send(const PubKey& dest, MsgType type, Channel, wire::View payload) override {
    mesh->route(self, dest, type, payload);
  }
  void broadcast(MsgType type, Channel, wire::View payload) override {
    mesh->broadcast(self, type, payload);
  }
};

inline void SimMesh::deliver(const PubKey& to, const PubKey& from, MsgType type, wire::View payload,
                             const MsgId& id) {
  // Models the transport invariant: dedup never suppresses local delivery of consensus
  // frames (liveness rebroadcasts are byte-identical); everything else delivers once.
  const bool fresh = seen[to].insert(id);
  const bool consensus = (type == MsgType::Consensus || type == MsgType::Prop);
  if (!fresh && !consensus) { ++seen_drop; return; }
  ++delivered;
  auto pit = ports.find(to);
  if (pit != ports.end() && pit->second->on_recv) pit->second->on_recv(from, type, payload);
}

inline void SimMesh::route(const PubKey& from, const PubKey& to, MsgType type, wire::View payload) {
  if (from == to) return;
  const MsgId id = make_msg_id(from, to, payload);
  if (linked(from, to)) {
    if (loss()) { ++lost; return; }
    deliver(to, from, type, payload, id);
    return;
  }
  for (const auto& r : members) {
    if (r == from || r == to) continue;
    if (linked(from, r) && linked(r, to)) {
      if (loss()) { ++lost; return; }
      ++relay_count;
      if (loss()) { ++lost; return; }
      deliver(to, from, type, payload, id);
      return;
    }
  }
  ++dropped_no_relay;
}

} // namespace hyle::morphe
