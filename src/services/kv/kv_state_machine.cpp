#include <hyle/services/kv/kv_state_machine.h>

namespace hyle {

wire::Bytes KvStateMachine::build_payload(uint64_t) {
  wire::Bytes payload = encode_ops(pending_);
  pending_.clear();
  return payload;
}

bool KvStateMachine::validate_payload(wire::View payload) {
  try {
    decode_ops(payload);
    return true;
  } catch (const wire::Error&) {
    return false;
  }
}

void KvStateMachine::apply_payload(const ApplyContext&, wire::View payload) {
  state_.apply(decode_ops(payload));
}

void KvStateMachine::restore(wire::View bytes) { state_.restore(bytes); }

} // namespace hyle
