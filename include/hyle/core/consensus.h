#ifndef HYLE_CONSENSUS_H
#define HYLE_CONSENSUS_H

#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <utility>
#include <vector>

namespace hyle::consensus {

struct Validator {
  std::array<uint8_t, 32> key{};
  uint64_t power = 1;
  bool operator==(const Validator&) const = default;
};

using ValidatorSet = std::vector<Validator>;

// A membership change decided at height H takes effect at height H + delay (default 2).
class ValidatorSetSchedule {
public:
  explicit ValidatorSetSchedule(ValidatorSet genesis, uint64_t initialHeight = 1,
                                unsigned delay = 2);

  // Heights must be non-decreasing and >= initialHeight.
  void onDecided(uint64_t decidedHeight, const ValidatorSet& committedSet);

  const ValidatorSet& setForHeight(uint64_t height) const;

  // Bypasses the initialHeight guard; caller ensures consistency.
  void set_change(uint64_t effectiveHeight, const ValidatorSet& set);

  unsigned delay() const { return delay_; }
  uint64_t initialHeight() const { return initialHeight_; }

private:
  ValidatorSet genesis_;
  uint64_t initialHeight_;
  unsigned delay_;
  std::map<uint64_t, ValidatorSet> effective_;
  uint64_t lastDecided_ = 0;
};

class Governance {
public:
  enum class Kind : uint8_t { Add = 0, Remove = 1 };
  using Id = std::array<uint8_t, 32>;
  using Member = std::pair<Id, Id>;  // (member id, associated data)

  Governance(const std::vector<Member>& genesis, unsigned cap, unsigned floor = 1);

  // Idempotent per voter+proposal.
  bool vote(const Id& voter, Kind kind, const Id& target, const Id& data = Id{});

  std::vector<Member> members() const;  // ascending by id
  bool isMember(const Id& id) const;
  size_t size() const;
  unsigned cap() const { return cap_; }
  unsigned floor() const { return floor_; }

  struct PendingVote {
    Kind kind;
    Id target;
    Id data;
    std::vector<Id> voters;
  };
  std::vector<PendingVote> pending() const;              // canonical order
  void set_pending(const std::vector<PendingVote>& v);

private:
  struct PropKey {
    Kind kind;
    Id target;
    Id data;
    bool operator<(const PropKey& o) const;
  };
  unsigned quorum() const;
  bool settle();

  std::map<Id, Id> members_;
  std::map<PropKey, std::set<Id>> votes_;
  unsigned cap_, floor_;
};

} // namespace hyle::consensus

#endif
