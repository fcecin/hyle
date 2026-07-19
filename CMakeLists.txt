cmake_minimum_required(VERSION 3.28)
project(hyle LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(HYLE_MARCH "x86-64-v3" CACHE STRING "Target -march")
add_compile_options(-march=${HYLE_MARCH})

include(FetchContent)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

find_package(Threads REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.83.0 REQUIRED COMPONENTS system log log_setup)

# CryptoPP: ed25519 + sha256. Pinned to an exact commit: consensus-critical, an
# upstream change to the ed25519/sha256 path could shift the AppHash.
FetchContent_Declare(
  cryptopp-cmake
  GIT_REPOSITORY https://github.com/abdes/cryptopp-cmake.git
  GIT_TAG        866aceb8b13b6427a3c4541288ff412ad54f11ea
)
set(CRYPTOPP_BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(cryptopp-cmake)

# malachite-cpp: the BFT consensus core. Needs a Rust toolchain on PATH.
FetchContent_Declare(
  malachitecpp
  GIT_REPOSITORY https://github.com/fcecin/malachite-cpp.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(malachitecpp)

# CLI11: the morphe executable's command tree. Product binary only.
FetchContent_Declare(
  cli11_proj
  GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
  GIT_TAG        v2.6.1
)
FetchContent_MakeAvailable(cli11_proj)

# Layer 1: hyle, the core. BFT consensus + governance + snapshot,
# application-agnostic and transport-agnostic.
add_library(hyle STATIC
  src/core/version.cpp
  src/core/blog.cpp
  src/core/crypto.cpp
  src/core/consensus.cpp
  src/core/snapshot.cpp
  src/core/node.cpp
)
target_include_directories(hyle PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(hyle PUBLIC
  malachite::cpp
  cryptopp::cryptopp
  Boost::headers
  Boost::system
  Boost::log
  Boost::log_setup
  Threads::Threads
)

# Layer 2: hyle_services, the transport-agnostic node facilities on the base.
add_library(hyle_services STATIC
  # kv module: generic state store, ops, the minimal KV state machine
  src/services/kv/ops.cpp
  src/services/kv/state.cpp
  src/services/kv/kv_state_machine.cpp
  # the account/entry economy schema
  src/services/app.cpp
  src/services/ops.cpp
  src/services/genesis.cpp
  # node machinery
  src/services/mempool.cpp
  src/services/runtime.cpp
  src/services/sync.cpp
  # util
  src/services/keys.cpp
  src/services/keyring.cpp
)
target_link_libraries(hyle_services PUBLIC hyle)

# The morphe shell and the tests build only when hyle is the top-level project.
# An embedder that FetchContents hyle gets core + hyle_services and brings its own shell.
if(PROJECT_IS_TOP_LEVEL)
  # Layer 3: hyle_morphe, the shell. Concrete TCP transport (AsioMesh),
  # RPC/REST surfaces, testnet generator, CLI. The morphe executable is the product.
  add_library(hyle_morphe STATIC
    src/morphe/frame.cpp
    src/morphe/asio_mesh.cpp
    src/morphe/testnet.cpp
    src/morphe/rpc.cpp
    src/morphe/rpc_server.cpp
    src/morphe/client_rest.cpp
  )
  target_link_libraries(hyle_morphe PUBLIC hyle_services)

  add_executable(morphe src/morphe/main.cpp src/morphe/manual.cpp)
  target_link_libraries(morphe PRIVATE hyle_morphe CLI11::CLI11)

  # techne: the client. Holds a keyring; talks to a node's REST + control ports.
  add_executable(techne src/techne/main.cpp)
  target_link_libraries(techne PRIVATE hyle_morphe CLI11::CLI11)

  enable_testing()
  add_subdirectory(tests)
endif()
