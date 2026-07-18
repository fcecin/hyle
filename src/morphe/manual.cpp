#include <hyle/morphe/manual.h>

#include <map>

namespace hyle::morphe::manual {

namespace {

const std::vector<std::pair<std::string, std::string>>& kToc() {
  static const std::vector<std::pair<std::string, std::string>> toc = {
      {"overview", "what Morphe is and how the pieces fit"},
      {"quickstart", "get a chain running and query it in under a minute"},
      {"concepts", "accounts vs entries, the KV state, height, AppHash"},
      {"economy", "credit issuance, fees, transfers, entries, rent, sequences"},
      {"keys", "identity, the node key, addressing accounts"},
      {"running", "init vs testnet, the home directory, solo vs networked"},
      {"config", "every config.txt setting"},
      {"networking", "the two-hop signed mesh, peers, ports"},
      {"consensus", "BFT, proposers, PBTS timestamps, fault tolerance"},
      {"governance", "membership: add, remove, leave"},
      {"rpc", "the JSON-RPC / WebSocket / metrics / health surface"},
      {"security", "what is signed, admin auth, evidence"},
      {"operating", "talk to a running node: status, query, tx, gov"},
      {"glossary", "terms in one place"},
  };
  return toc;
}

const std::map<std::string, std::string>& kBody() {
  static const std::map<std::string, std::string> body = {

      {"overview",
       R"(MORPHE -- overview

Morphe is a standalone node for a permissioned, in-RAM BFT key-value blockchain. One `morphe` binary is
a full validator: it forms a network with peers, runs Byzantine-fault-tolerant consensus, and applies
each committed block to a replicated key-value store. There is no disk state and no history replay --
durability is replication across peers, and a new node joins by adopting a snapshot.

Layers (you only run the top one):
  - core   : the BFT consensus engine + governance + snapshot machinery (generic).
  - kv     : the in-RAM key-value store the state machine writes to.
  - morphe : THIS product -- an account/entry economy imposed on the store, a signed TCP mesh, an RPC
             surface, and this CLI.

What a chain agrees on: a height (block number), the set of validators, and a single composite hash
(the AppHash) over all state at that height. Survives losing under 1/3 of its validators.

Start here: `morphe man quickstart`, then `morphe man concepts` and `morphe man economy`.)"},

      {"quickstart",
       R"(MORPHE -- quickstart

Two binaries: `morphe` is the SERVER (runs a node); `techne` is the CLIENT (submits + queries).

A0. Single node = a local in-RAM KV store (no network, self-quorum):
     morphe init db                 # writes db/{node.key,genesis.txt,config.txt} with both ports on
     morphe start db                # solo: paces one block per block_pace_ms when idle, drains txs fast
   Then, as a client (control_port 46000, client_port 47000 by default):
     export TECHNE_MORPHE_CONTROL=127.0.0.1:46000 TECHNE_MORPHE_NODE=127.0.0.1:47000
     techne key gen alice
     techne tx transfer --key db/node.key @alice 500 && techne query balance @alice
   Durability is an EXTERNAL harness's job (Morphe keeps no disk): dump/restore the whole state --
     techne snapshot dump /tmp/db.snap        # then you may kill -9 the node
     morphe start db & techne snapshot load /tmp/db.snap   # fresh node, state back, resumes committing
   A one-validator chain is not replicated/reliable; it is an in-RAM DB with a snapshot command.

A. Local 4-node testnet:
     morphe testnet 4 tn 40000      # writes tn/node0..node3 (control_port base+1000, client_port base+2000)
     morphe up tn                   # start AND supervise all four nodes; Ctrl-C stops them all
     morphe doctor tn/node0         # (another shell) height advancing? RPC up?

B. Act on it as a client (techne):
     export TECHNE_MORPHE_NODE=127.0.0.1:42000            # node0's client_port (base 40000 + 2000)
     techne key gen alice                           # a client identity in the keyring
     # fund alice from a validator's key (validators are seeded in genesis):
     techne tx transfer --key tn/node0/node.key @alice 500
     techne query balance @alice                    # -> 500
     techne tx transfer --key alice @alice 0        # alice can now transact; seq auto-fills

   @name resolves a keyring identity's pubkey; @path/to/home resolves a node's node.key. No hex pasting.

Everything else: `morphe man <topic>`, `techne man`, `morphe --help`, `techne --help`.)"},

      {"concepts",
       R"(MORPHE -- concepts

STATE is a key-value store. Every key begins with a 1-byte prefix:
  'a' + 32-byte pubkey  = an ACCOUNT. The pubkey IS an identity (an ed25519 public key). Accounts are
                          non-squattable: you can only ever fund the key you hold. Value = {balance,
                          sequence}.
  'e' + arbitrary bytes = an ENTRY. The bytes are a content key (a name, an id, anything). Entries are
                          squattable (first to fund a name owns it). Value = {owner, balance, created,
                          last_modified, last_rent, payload}. An entry holds its OWN balance and pays
                          its own rent.

HEIGHT is the block number; it only goes up. Each committed block advances it by one.

APPHASH is a single sha256 over ALL state (governance + application) at a height. Every honest node
computes the same AppHash for the same height -- that is how they prove they agree. `morphe query
apphash <home>` prints it.

SEQUENCE (nonce) is the replay guard: every signed op from an account carries the account's next
expected sequence, which then advances by one. A replayed or out-of-order op is rejected.

Next: `morphe man economy`.)"},

      {"economy",
       R"(MORPHE -- economy

The chain has its OWN native credit. Fees are FIXED and BURNED (removed from circulation).

ISSUANCE (where credit enters). Two sources, both on-chain:
  - Per-block autofill: every block, each validator balance is topped toward credit_autofill_ceiling
    (see genesis config). A node that runs the chain is thereby self-funding.
  - Governance: a sudo act transferring FROM the all-zero mint sentinel creates credit into any
    account (the sentinel is never debited). See `morphe man governance`.
There is no proof-of-work and no client-side mining.

TRANSFER: signed by the source account; moves credit to any key.
  - to an ACCOUNT ('a'+pubkey): credits it (creates it if absent).
  - to an ENTRY  ('e'+name)   : CREATES the entry (owner = sender) if absent, else tops up its balance.
    Any funded key may fund an entry (third-party rent funding).
  Pays amount + fee_transfer (fee burned); advances the sender's sequence.

ENTRIES: `entry-put` (owner) writes the payload and can fund it; `entry-del` deletes it and refunds the
residual balance to the owner; ownership can be given away; a starved entry can be permissionlessly
purged ("ripped") for a bounty.

RENT: if rent_rate > 0, an entry pays rate * footprint * elapsed-time out of its balance, rolled lazily
whenever it is touched. When its balance hits zero with rent owed, it becomes rippable. Rent uses the
committed PBTS wall-clock (see `morphe man consensus`), not local time, so it is deterministic.

Off-chain bridge: a user pays a server in that server's own credit; the server submits an on-chain
transfer from its own balance. The chain never measures cross-server credit.)"},

      {"keys",
       R"(MORPHE -- keys and identity

A node's identity IS an ed25519 key pair. The public key is the node's validator identity, its mesh
address, AND its on-chain account. There is no separate wallet for a node -- one key does everything.

  morphe keygen [file]        # generate a key (default: node.key), hex private key, chmod 0600
  morphe init <home>          # also generates <home>/node.key for you
  morphe pubkey [home]        # print the public key (the account / identity) for a home's node.key
  morphe whoami [home]        # alias for pubkey

The private key lives in <home>/node.key as 64 hex chars on one line (0600 perms). Guard it: whoever
holds it IS that validator and can spend that account. To reference an account on the CLI you paste its
64-hex pubkey; `morphe pubkey <home>` prints yours so you never have to remember it.

(There is no multi-key wallet in v1: a node is one identity. A client that wants many accounts runs many
keys / homes.)  Env var: set MORPHE_HOME to a directory and home-taking commands default to it.)"},

      {"running",
       R"(MORPHE -- running a node

A node is a HOME DIRECTORY plus the binary. `morphe start <home>` reads:
  <home>/node.key      the identity (private key, hex).
  <home>/genesis.txt   the chain definition (chain_id, validators, allocations, economic params). All
                       nodes on a chain MUST share the byte-identical genesis; `morphe genesis hash`
                       proves it.
  <home>/config.txt    node-local settings (see `morphe man config`).
  <home>/peers.txt     the other members' identities + endpoints. If PRESENT, the node runs networked
                       (real TCP mesh); if ABSENT, it runs solo (single validator, self-quorum).
  <home>/evidence/     double-sign evidence files land here (see `morphe man security`).

A SOLO node (no peers.txt) is a single self-quorum validator: no mesh, but it still serves its ports, so
one node is a usable local in-RAM KV store (query/write/snapshot). It paces one block per block_pace_ms
when idle and drains pending txs promptly. Add peers.txt to make it one validator of a replicated mesh.

Two ways to create a home:
  morphe init <home>              one solo validator with control+client ports on; a local in-RAM DB.
  morphe testnet <n> <dir> <port> n node homes that share a genesis and know each other as peers, on
                                  loopback (node i: mesh port+i, control_port port+1000+i, client_port
                                  port+2000+i).

`morphe start` logs structured JSON lines to stdout (node_start, block_decided, tx_committed,
peers_changed, control_listen, client_listen). Redirect to a file or your log system.)"},

      {"config",
       R"(MORPHE -- config.txt

One "key value" per line (NOT TOML). Missing keys use the default. Economic params are NOT here -- they
are genesis-fixed (same on every node); see genesis.txt. config.txt is node-LOCAL:

  block_pace_ms <ms>     heartbeat pace for a SOLO node's empty blocks (default 1000). Networked nodes
                         commit as fast as consensus allows.
  listen_port <port>     TCP port for the mesh (networked nodes). 0 = an ephemeral port.
  control_port <port>    CONTROL port: JSON-RPC (queries + gov/leave/snapshot) + metrics/health, bound
                         to 127.0.0.1. Absent = off. NO auth -- FIREWALL this port; never expose it.
                         `morphe testnet` sets base+1000+i.
  client_port <port>     CLIENT port: a small public REST surface (queries + tx submit only, no control
                         ops). Absent = off. Safe to expose (every tx is fee-gated). testnet: base+2000+i.
  client_bind <addr>     bind address for the client port (default 0.0.0.0).

`peers.txt`: one peer per line, "<pubkey_hex> <host> <port>".
`genesis.txt`: chain_id, one `validator <hex>` per member, `alloc <hex> <amount>` seeds, and the fee /
rent / autofill parameters. `morphe genesis validate <path>` checks it.)"},

      {"networking",
       R"(MORPHE -- networking (the mesh)

Transport is a persistent, authenticated, UNENCRYPTED TCP mesh (everything on a public chain is public;
authenticity matters, secrecy does not). At most two hops: if A has no direct link to B, it relays via
one member. Deterministic addressed forwarding, not gossip.

HANDSHAKE: on connect, each side proves it holds its claimed identity's private key via a mutual
challenge-response (each signs the other's fresh random nonce). Only configured members that pass this
are admitted; an impostor without the key, or an outsider not in peers.txt, is dropped. This is why the
transport is safe despite being plaintext -- you cannot spoof a member.

Every message carries its author identity. Self-authenticating payloads (votes, proposals, txs) carry
their own signatures, so a relay can never forge or tamper with them.

Config: listen_port (this node) and peers.txt (the others). A partition or lost link is tolerated by
BFT as long as more than 2/3 of validators remain mutually reachable.)"},

      {"consensus",
       R"(MORPHE -- consensus

Byzantine-fault-tolerant (Tendermint-class). Validators take turns proposing a block; a block commits
when more than 2/3 of validators PRECOMMIT it (all votes signed). The chain is safe (no two honest nodes
disagree on a height) as long as fewer than 1/3 of validators are Byzantine, and live once the network
stabilizes. With n validators it tolerates f = floor((n-1)/3) faults.

PROPOSER: one designated validator proposes each height/round. The proposal is SIGNED by that proposer,
so no one else can substitute a block into its slot. A stuck round times out and moves to the next
proposer.

PBTS (proposer-based timestamps): each block carries the proposer's wall-clock time, which validators
accept only if it is within a window of their own clock and not before the parent's time. This gives
the chain a consensus-VALIDATED wall-time (used for rent, and for cross-chain earliest-wins ordering)
without letting time drive block ordering. Low resolution is fine.

"Slowness is free": correctness never depends on timing, only on the >2/3 quorum. Pace blocks to the
node count if you like; the invariants hold regardless.)"},

      {"governance",
       R"(MORPHE -- governance (membership)

The ONLY on-chain governance is the validator set. There is no parameter governance. Members vote to
add or remove members; a change needs a supermajority (> 2/3 of current members) and takes effect two
heights after it is decided (so in-flight blocks are unambiguous). A floor prevents removing below a
minimum viable set.

Votes are control ops, issued via a node's CONTROL port using the client binary:
  techne gov vote add --morphe-control host:<control_port> <pubkey|@name>       # admit a validator
  techne gov vote remove --morphe-control host:<control_port> <pubkey|@name>    # remove one
(each current validator's operator runs this against their own node; a supermajority must concur.)

A single vote is not enough -- a supermajority must concur. Votes ride inside committed blocks (signed
gov ops). A removed validator stops being asked to propose/vote; a newly added one joins by adopting a
snapshot (it does not replay history) and validating forward. A node that just wants to stop can freeze;
the set will carry on with its remaining 2/3.)"},

      {"rpc",
       R"(MORPHE -- RPC / WebSocket / metrics / health

A node serves up to two INDEPENDENT ports, each optional (see config.txt).

CONTROL port (control_port, bound 127.0.0.1, NO auth -- firewall it):
  HTTP POST /            JSON-RPC 2.0. Everything: submit_tx, query.*, status, and control methods
                         admin.{snapshot_dump,snapshot_load,gov_vote,leave,shutdown} (set_log_level is
                         reserved: it replies ok:false / "not implemented" until the log wiring lands).
  WebSocket /            subscribe to event topics: {"method":"subscribe","params":{"topic":"height"}}.
  GET /metrics           Prometheus: morphe_{height,mempool_size,peers,validators,evidence_count,...}.
  GET /health            200 {live,ready} once the node has a height, 503 while it has none.

CLIENT port (client_port, public REST) -- DELIBERATELY MINIMAL. Every route is a cheap, bounded O(1)
lookup (or one signature verify for submit); request bodies are capped (64 KiB). Nothing that
enumerates, aggregates, or streams is here:
  POST /tx               body = signed op bytes (hex) -> {tx_id, accepted, reason}
  GET  /height                                        (confirmations / liveness)
  GET  /balance/<pubkey> /account/<pubkey> /entry/<name> /tx/<id>   (bare JSON, no envelope)

Introspection (validators, apphash, status, mempool, governance) and any event stream are NOT on the
public port -- they live on the CONTROL port. An unpaid public event feed / heavy scan is a classic
abuse vector, so the public surface stays to the client-essential per-key reads.

Clients use the `techne` binary (or plain curl) against these ports. `morphe` itself is server-only.)"},

      {"security",
       R"(MORPHE -- security model

AUTHENTICATION invariant: every message that crosses a trust boundary is signed. Votes and proposals
are signed by validators (verified by consensus); the proposal wrapper (Prop) is signed by the proposer,
who must also be a validator for that height; transactions are signed by the operating key (verified at
admission and apply); the mesh handshake is a challenge-response proof-of-possession, and a peer cannot
forge the source of a direct frame. Consensus safety rests on these signatures, not on the transport.

NO ENCRYPTION: a public chain's data is public. The mesh is authenticated but plaintext. Do not put
secrets on-chain.

CONTROL is gated by DEPLOYMENT, not by a token. The control_port (gov/leave/snapshot/shutdown) has NO
in-process auth: if you can reach it, you can drive the node. Bind it to loopback/internal and FIREWALL
it -- exactly as real blockchain stacks do (an internet-exposed admin RPC invites exhaustion attacks; a
token on a reachable port only makes control programs harder to write). The client_port carries no
control ops and is anti-spam-gated by fees, so it is safe to expose.

EVIDENCE: if a node sees a validator sign two different proposals at the same height/round, it writes a
double-sign evidence file to <home>/evidence/. In v1 this is a local diagnostic (no automatic slashing).

Keys: a node's private key IS its authority. Protect <home>/node.key.)"},

      {"operating",
       R"(MORPHE -- operating a running node

`morphe` is a SERVER; it does not talk to nodes. To act on a running chain (submit txs, query, vote)
use the CLIENT binary, `techne` (see `techne man`). It holds identities in a keyring and talks to a
node's ports:

  export TECHNE_MORPHE_NODE=host:<client_port>     # public REST: tx + query
  techne key gen alice                       # a client identity ($TECHNE_KEYS or ~/.morphe/keys)
  techne tx transfer --key alice @bob 100    # sign as alice, send to keyring bob; seq auto-fills
  techne query balance @bob                  # read it back
  techne gov vote add --morphe-control host:<control_port> @newvalidator   # control ops go to control_port

On the SERVER side, to inspect a node locally:
  morphe config <home>     effective config: ports, pace, genesis, peers
  morphe doctor <home>     diagnose key/genesis/config and (if running) control RPC + liveness
  morphe pubkey <home>     the node's identity (alias whoami)

Or curl the ports directly: control_port is JSON-RPC (firewalled); client_port is REST (see `man rpc`).)"},

      {"glossary",
       R"(MORPHE -- glossary

account      an 'a'+pubkey key; balance + sequence; non-squattable (only the key holder funds it).
entry        an 'e'+name key; owner + balance + payload; squattable; pays its own rent.
AppHash      one sha256 over all state at a height; equal across honest nodes = they agree.
height       block number; monotonic.
sequence     per-account nonce; replay guard for signed ops.
autofill     per-block top-up of each validator toward the credit ceiling; the issuance source.
fee          fixed per-op charge, BURNED (removed from supply).
rent         time-based drain on an entry's balance; deterministic via the committed PBTS time.
rip          permissionless purge of a starved entry for a bounty.
proposer     the validator that proposes a given block; its proposal is signed.
PBTS         proposer-based timestamp: a consensus-validated wall-clock in each block.
quorum       > 2/3 of validators; needed to commit and to change membership.
f            tolerated faults = floor((n-1)/3) for n validators.
snapshot     the full state at a height; how a joiner catches up (no history replay).
evidence     a local file recording an observed double-sign.
home         a directory holding node.key + genesis.txt + config.txt (+ peers.txt).
member       a current validator (a runtime fact from governance, not a config role).)"},
  };
  return body;
}

}  // namespace

const std::vector<std::pair<std::string, std::string>>& topics() { return kToc(); }

const std::string* lookup(const std::string& name) {
  const auto& b = kBody();
  auto it = b.find(name);
  return it == b.end() ? nullptr : &it->second;
}

} // namespace hyle::morphe::manual
