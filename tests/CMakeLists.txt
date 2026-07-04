# Filter by suite name: ./build.sh debug --test <SuiteName>
add_executable(hyletests
  tests_main.cpp
  test_smoke.cpp
  test_crypto.cpp
  test_state.cpp
  test_node.cpp
  test_consensus.cpp
  test_governance.cpp
  test_snapshot.cpp
  test_base.cpp
  test_ledger.cpp
  test_registry.cpp
  test_sync.cpp
  test_mint.cpp
  test_stress.cpp
  test_sim.cpp
  test_votewal.cpp
)
target_link_libraries(hyletests PRIVATE
  hyle_services
  Boost::system
)
add_test(NAME hyletests COMMAND hyletests)

# embedtests: proves core + services alone are a working node. Links hyle_services,
# never hyle_morphe, so a services->shell dependency would fail to link.
add_executable(embedtests
  tests_main.cpp
  test_embed.cpp
)
target_link_libraries(embedtests PRIVATE hyle_services Boost::system)
add_test(NAME embedtests COMMAND embedtests)

# Morphe (layer 3) has its own test binary.
add_executable(morphetests
  tests_main.cpp
  test_morphe.cpp
)
target_link_libraries(morphetests PRIVATE
  hyle_morphe
  Boost::system
)
add_test(NAME morphetests COMMAND morphetests)

# e2etests: black-box end-to-end. Launches the real morphe and techne binaries
# and drives scenarios over TCP. Run explicitly (./build/<cfg>/tests/e2etests) or via ctest.
add_executable(e2etests
  tests_main.cpp
  test_e2e.cpp
)
target_link_libraries(e2etests PRIVATE hyle_morphe Boost::system)
add_dependencies(e2etests morphe techne)
add_test(NAME e2etests COMMAND e2etests)
