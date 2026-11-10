#include <hyle/services/mempool.h>

#include <hyle/services/schema.h>

#include <algorithm>

namespace hyle::services {

const char* admit_reason(Admit a) {
  switch (a) {
    case Admit::Ok: return "ok";
    case Admit::Full: return "mempool full";
    case Admit::BadShape: return "bad shape";
    case Admit::BadSig: return "bad signature";
    case Admit::SeqStale: return "stale nonce";
    case Admit::SeqGap: return "nonce gap";
    case Admit::InsufficientFunds: return "insufficient funds";
    case Admit::Duplicate: return "duplicate";
  }
  return "unknown";
}

namespace {
uint64_t sat_add(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }
}

Hash Mempool::id_of(wire::View sign_bytes, const Sig& sig) const {
  wire::Bytes buf(sign_bytes.begin(), sign_bytes.end());
  buf.insert(buf.end(), sig.begin(), sig.end());
  return sha256(wire::View(buf.data(), buf.size()));
}

Admit Mempool::admit_transfer(const TransferOp& op, uint64_t committed_seq,
                              uint64_t committed_balance) {
  if (order_.size() >= cap_) return Admit::Full;
  if (!valid_transfer_dest(wire::View(op.to.data(), op.to.size()))) return Admit::BadShape;

  const wire::Bytes sb =
      xfer_sign_bytes(chain_v(), op.from, wire::View(op.to.data(), op.to.size()), op.amount, op.seq, op.max);
  if (!verify(op.from, wire::View(sb.data(), sb.size()), op.sig)) return Admit::BadSig;

  const Hash id = id_of(wire::View(sb.data(), sb.size()), op.sig);
  if (seen(id)) return Admit::Duplicate;

  auto ns = next_seq_.find(op.from);
  const uint64_t expected = ns != next_seq_.end() ? ns->second : committed_seq;
  if (op.seq < expected) return Admit::SeqStale;
  if (op.seq > expected) return Admit::SeqGap;

  const uint64_t cost = sat_add(op.amount, cfg_.fee_transfer);
  const uint64_t pending = debit_.count(op.from) ? debit_[op.from] : 0;
  const uint64_t avail = committed_balance > pending ? committed_balance - pending : 0;
  uint64_t reserve = cost;
  if (op.max) {
    if (reserve > avail) reserve = avail;   // max takes at most what is left
  } else if (avail < cost) {
    return Admit::InsufficientFunds;
  }

  order_.push_back({Kind::Transfer, transfers_.size(), id, true, op.from, op.seq, reserve});
  transfers_.push_back(op);
  seen_.insert(id);
  next_seq_[op.from] = op.seq + 1;
  debit_[op.from] = sat_add(pending, reserve);
  return Admit::Ok;
}

Admit Mempool::admit_entry(const EntryOp& op, uint64_t committed_seq, uint64_t committed_balance) {
  if (order_.size() >= cap_) return Admit::Full;
  if (op.name.empty()) return Admit::BadShape;

  if (op.kind == EntryKind::Rip) {
    const Hash id = id_of(wire::View(op.name.data(), op.name.size()), op.sig);
    if (seen(id)) return Admit::Duplicate;
    order_.push_back({Kind::Entry, entries_.size(), id, false, PubKey{}, 0, 0});
    entries_.push_back(op);
    seen_.insert(id);
    return Admit::Ok;
  }

  const wire::Bytes sb =
      entry_sign_bytes(chain_v(), op.kind, op.signer, wire::View(op.name.data(), op.name.size()), op.seq,
                       op.amount, op.aux, wire::View(op.payload.data(), op.payload.size()));
  if (!verify(op.signer, wire::View(sb.data(), sb.size()), op.sig)) return Admit::BadSig;

  const Hash id = id_of(wire::View(sb.data(), sb.size()), op.sig);
  if (seen(id)) return Admit::Duplicate;

  auto ns = next_seq_.find(op.signer);
  const uint64_t expected = ns != next_seq_.end() ? ns->second : committed_seq;
  if (op.seq < expected) return Admit::SeqStale;
  if (op.seq > expected) return Admit::SeqGap;

  const uint64_t move = op.kind == EntryKind::Put ? op.amount : 0;
  const uint64_t cost = sat_add(move, cfg_.fee_entry);
  const uint64_t pending = debit_.count(op.signer) ? debit_[op.signer] : 0;
  if (committed_balance < sat_add(pending, cost)) return Admit::InsufficientFunds;

  order_.push_back({Kind::Entry, entries_.size(), id, true, op.signer, op.seq, cost});
  entries_.push_back(op);
  seen_.insert(id);
  next_seq_[op.signer] = op.seq + 1;
  debit_[op.signer] = sat_add(pending, cost);
  return Admit::Ok;
}

Admit Mempool::admit_sudo(const SudoOp& op, uint64_t committed_seq, uint64_t committed_balance) {
  if (order_.size() >= cap_) return Admit::Full;
  if (op.kind == SudoKind::Propose) {
    if (op.proposer != op.signer) return Admit::BadShape;
    const wire::View inner(op.inner.data(), op.inner.size());
    if (op.inner_hash != sha256(inner)) return Admit::BadShape;
    if (!valid_sudo_inner(inner)) return Admit::BadShape;  // never admit a proposal that cannot apply
  }

  const wire::Bytes sb =
      sudo_sign_bytes(chain_v(), op.kind, op.signer, op.seq, op.proposer, op.inner_hash);
  if (!verify(op.signer, wire::View(sb.data(), sb.size()), op.sig)) return Admit::BadSig;

  const Hash id = id_of(wire::View(sb.data(), sb.size()), op.sig);
  if (seen(id)) return Admit::Duplicate;

  auto ns = next_seq_.find(op.signer);
  const uint64_t expected = ns != next_seq_.end() ? ns->second : committed_seq;
  if (op.seq < expected) return Admit::SeqStale;
  if (op.seq > expected) return Admit::SeqGap;

  const uint64_t pending = debit_.count(op.signer) ? debit_[op.signer] : 0;
  if (committed_balance < sat_add(pending, cfg_.fee_sudo)) return Admit::InsufficientFunds;

  order_.push_back({Kind::Sudo, sudos_.size(), id, true, op.signer, op.seq, cfg_.fee_sudo});
  sudos_.push_back(op);
  seen_.insert(id);
  next_seq_[op.signer] = op.seq + 1;
  debit_[op.signer] = sat_add(pending, cfg_.fee_sudo);
  return Admit::Ok;
}

Decoded Mempool::snapshot() const {
  Decoded d;
  for (const Slot& s : order_) {
    switch (s.kind) {
      case Kind::Transfer: d.transfers.push_back(transfers_[s.idx]); break;
      case Kind::Entry: d.entries.push_back(entries_[s.idx]); break;
      case Kind::Sudo: d.sudos.push_back(sudos_[s.idx]); break;
    }
  }
  return d;
}

Decoded Mempool::drain(size_t max) {
  Decoded d;
  const size_t n = std::min(max, order_.size());
  std::vector<TransferOp> transfers;
  std::vector<EntryOp> entries;
  std::vector<SudoOp> sudos;
  std::vector<Slot> order;
  seen_.clear();
  next_seq_.clear();
  debit_.clear();
  for (size_t i = 0; i < order_.size(); ++i) {
    Slot s = order_[i];
    if (i < n) {
      switch (s.kind) {
        case Kind::Transfer: d.transfers.push_back(std::move(transfers_[s.idx])); break;
        case Kind::Entry: d.entries.push_back(std::move(entries_[s.idx])); break;
        case Kind::Sudo: d.sudos.push_back(std::move(sudos_[s.idx])); break;
      }
      continue;
    }
    const size_t from = s.idx;
    switch (s.kind) {
      case Kind::Transfer:
        s.idx = transfers.size();
        transfers.push_back(std::move(transfers_[from]));
        break;
      case Kind::Entry:
        s.idx = entries.size();
        entries.push_back(std::move(entries_[from]));
        break;
      case Kind::Sudo:
        s.idx = sudos.size();
        sudos.push_back(std::move(sudos_[from]));
        break;
    }
    seen_.insert(s.id);
    if (s.sequenced) {
      next_seq_[s.signer] = s.seq + 1;
      debit_[s.signer] = sat_add(debit_[s.signer], s.reserve);
    }
    order.push_back(s);
  }
  transfers_ = std::move(transfers);
  entries_ = std::move(entries);
  sudos_ = std::move(sudos);
  order_ = std::move(order);
  return d;
}

} // namespace hyle::services
