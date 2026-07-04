#include <hyle/core/consensus.h>

#include <hyle/core/blog.h>

LOG_MODULE_DISABLED("hyle.gov")

namespace hyle::consensus {

ValidatorSetSchedule::ValidatorSetSchedule(ValidatorSet genesis, uint64_t initialHeight,
                                           unsigned delay)
    : genesis_(std::move(genesis)), initialHeight_(initialHeight),
      delay_(delay == 0 ? 1 : delay) {}

void ValidatorSetSchedule::onDecided(uint64_t decidedHeight, const ValidatorSet& committedSet) {
  if (decidedHeight < initialHeight_) return;
  if (decidedHeight < lastDecided_) {
    LOGWARNING << "schedule: onDecided height " << decidedHeight << " < last decided "
               << lastDecided_ << " (ignored; non-decreasing invariant violated)";
    return;
  }
  lastDecided_ = decidedHeight;
  const uint64_t effHeight = decidedHeight + delay_;
  if (committedSet == setForHeight(effHeight - 1)) return;
  effective_[effHeight] = committedSet;
  LOGTRACE << "schedule: validator set change effective at height " << effHeight << " ("
           << committedSet.size() << " validators)";
}

const ValidatorSet& ValidatorSetSchedule::setForHeight(uint64_t height) const {
  if (effective_.empty()) return genesis_;
  auto it = effective_.upper_bound(height);
  if (it == effective_.begin()) return genesis_;
  --it;
  return it->second;
}

void ValidatorSetSchedule::set_change(uint64_t effectiveHeight, const ValidatorSet& set) {
  effective_[effectiveHeight] = set;
}

bool Governance::PropKey::operator<(const PropKey& o) const {
  if (kind != o.kind) return kind < o.kind;
  if (target != o.target) return target < o.target;
  return data < o.data;
}

Governance::Governance(const std::vector<Member>& genesis, unsigned cap, unsigned floor)
    : cap_(cap), floor_(floor < 1 ? 1 : floor) {
  for (const auto& m : genesis) members_[m.first] = m.second;
}

unsigned Governance::quorum() const {
  return static_cast<unsigned>((2 * members_.size()) / 3 + 1);
}

bool Governance::isMember(const Id& id) const { return members_.count(id) != 0; }
size_t Governance::size() const { return members_.size(); }

std::vector<Governance::Member> Governance::members() const {
  std::vector<Member> out;
  out.reserve(members_.size());
  for (const auto& kv : members_) out.push_back(kv);
  return out;
}

std::vector<Governance::PendingVote> Governance::pending() const {
  std::vector<PendingVote> out;
  out.reserve(votes_.size());
  for (const auto& [k, voters] : votes_) {
    PendingVote pv;
    pv.kind = k.kind;
    pv.target = k.target;
    pv.data = k.data;
    pv.voters.assign(voters.begin(), voters.end());
    out.push_back(std::move(pv));
  }
  return out;
}

void Governance::set_pending(const std::vector<PendingVote>& v) {
  votes_.clear();
  for (const auto& pv : v) {
    // a Remove carries no data, so zero it; else tallies never merge.
    PropKey key{pv.kind, pv.target, pv.kind == Kind::Add ? pv.data : Id{}};
    std::set<Id>& s = votes_[key];
    for (const auto& voter : pv.voters) s.insert(voter);
  }
  settle();
}

bool Governance::vote(const Id& voter, Kind kind, const Id& target, const Id& data) {
  if (!isMember(voter)) return false;
  if (kind == Kind::Add && isMember(target)) return false;
  if (kind == Kind::Remove && !isMember(target)) return false;
  PropKey key{kind, target, kind == Kind::Add ? data : Id{}};
  votes_[key].insert(voter);
  LOGTRACE << "governance: vote kind " << static_cast<int>(kind) << " tally " << votes_[key].size()
           << "/" << quorum() << VAL("target", target);
  return settle();
}

bool Governance::settle() {
  bool changedAny = false;
  for (bool applied = true; applied;) {
    applied = false;
    for (auto it = votes_.begin(); it != votes_.end();) {
      const PropKey& k = it->first;
      const bool dead = (k.kind == Kind::Add && isMember(k.target)) ||
                        (k.kind == Kind::Remove && !isMember(k.target));
      if (dead) {
        it = votes_.erase(it);
        continue;
      }
      if (it->second.size() >= quorum()) {
        if (k.kind == Kind::Add && members_.size() < cap_) {
          const Id added = k.target;  // copy before erase: k references the map node freed below
          members_[added] = k.data;
          votes_.erase(it);
          applied = true;
          changedAny = true;
          LOGDEBUG << "governance: quorum ADD, members now " << members_.size()
                   << VAL("member", added);
          break;
        }
        if (k.kind == Kind::Remove && members_.size() > floor_) {
          Id gone = k.target;
          members_.erase(gone);
          votes_.erase(it);
          for (auto& pv : votes_) pv.second.erase(gone);
          applied = true;
          changedAny = true;
          LOGDEBUG << "governance: quorum REMOVE, members now " << members_.size()
                   << VAL("member", gone);
          break;
        }
      }
      ++it;
    }
  }
  return changedAny;
}

} // namespace hyle::consensus
