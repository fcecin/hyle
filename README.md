# Hyle

**NOTE: This is experimental software.**

An in-RAM BFT consensus key-value store, built on [malachite-cpp](https://github.com/fcecin/malachite-cpp).

A single Byzantine-fault-tolerant chain whose replicated state machine is an in-memory key-value store with height, blocks, and membership governance (members vote to add and remove members). Shaped like CometBFT, but the application is fixed and there is no bytecode VM.

Hyle keeps no disk: state lives in RAM, and durability is replication across stable peers, not local persistence. A node that stops is ejected; a joiner rejoins from a current state snapshot and its commit certificate.

Three layers: the core library (`hyle`), the transport-agnostic node facilities (`hyle_services`), and the `morphe`/`techne` binaries (`hyle_morphe`).

## Build

Needs a C++20 compiler, CMake, Boost, and a Rust toolchain (malachite-cpp builds a staticlib).

```
./build.sh debug --test
```

## License

See [LICENSE](LICENSE).
