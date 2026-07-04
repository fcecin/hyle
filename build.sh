#!/bin/bash

# Build, test, or clean Hyle. Needs a Rust toolchain on PATH (malachite-cpp
# builds a staticlib via cargo).

set -e

print_help() {
    echo "Usage: $0 [target] [options] | [command]"
    echo ""
    echo "Targets (default 'debug' if a flag is present):"
    echo "  debug | release | relwithdebinfo | minsizerel"
    echo ""
    echo "Options:"
    echo "  --native          -march=native (local only; default x86-64-v3, portable)."
    echo "  --asan            AddressSanitizer (use-after-free, overflow, leaks)."
    echo "  --ubsan           UndefinedBehaviorSanitizer (combinable with --asan)."
    echo "  --tsan            ThreadSanitizer (data races). Run with 'setarch -R' if it reports"
    echo "                      'unexpected memory mapping'. Mutually exclusive with --asan."
    echo "  --test            Build, then run every test executable."
    echo "  --<name> [suite]  Build, then run one test executable (e.g. --hyletests),"
    echo "                      optionally filtered to a single Boost suite (e.g."
    echo "                      --hyletests ConsensusTests). Names are discovered from"
    echo "                      build/<target>/tests/; an unknown or not-yet-built name is"
    echo "                      rejected as an unknown switch."
    echo "  --clean           Clean the target before building."
    echo "  --rm              Delete 'build/' before building."
    echo "  --help, -h"
    echo ""
    echo "Commands:  clean (all targets)   rm (delete build/)"
    for d in build/*/tests; do
        [ -d "$d" ] || continue
        names=$(find "$d" -maxdepth 1 -type f -executable -printf '%f ' 2>/dev/null)
        [ -n "$names" ] && { echo ""; echo "Test executables in $d:"; echo "  $names"; break; }
    done
}

deep_clean_project() { echo "Deleting all builds..."; rm -rf build; echo "Done."; }
soft_clean_project() {
    echo "Cleaning all targets..."
    for dir in build/*/; do
        [ -d "$dir" ] && { echo "  cmake --build $dir --target clean"; cmake --build "$dir" --target clean 2>/dev/null || true; }
    done
}
clean_one_target() {
    local BUILD_DIR="build/$1"
    [ -d "$BUILD_DIR" ] && { echo "Cleaning $1..."; cmake --build "$BUILD_DIR" --target clean 2>/dev/null || true; }
}

# Run one Boost.Test executable, optionally filtered to a suite. Returns non-zero on failure.
run_test_exe() {
    local bin="$1" label="$2" suite="$3"
    local bargs="-l test_suite --report_level=short"
    [ -n "$suite" ] && bargs="$bargs --run_test=$suite"
    echo "--- Running $label ---"
    local logf; logf=$(mktemp "${TMPDIR:-/tmp}/hyletests.XXXXXX.log")
    set +e
    "$bin" $bargs 2>&1 | tee "$logf"
    local rc=${PIPESTATUS[0]}
    set -e
    local cases asserts summary failed
    cases=$(grep -aoE '[0-9]+ test cases? out of [0-9]+ (passed|failed)' "$logf" | tail -1)
    asserts=$(grep -aoE '[0-9]+ assertions? out of [0-9]+ (passed|failed)' "$logf" | tail -1)
    summary="$cases"; [ -n "$asserts" ] && summary="$summary; $asserts"
    failed=$(grep -aoE '\*\*\* [0-9]+ failures? (are|is) detected|has failed with' "$logf" | tail -1)
    if [ "$rc" -ne 0 ] || [ -n "$failed" ]; then
        echo "FAIL $label (exit $rc) -- ${summary:-see output above}"
        echo "   log: $logf"; return 1
    fi
    rm -f "$logf"; echo "OK $label passed -- ${summary:-no tally}"
}

build_one_config() {
    local LOWER="$1" CAMEL="$2" BUILD_DIR="build/$1" EXTRA_ARGS=""

    # asan+ubsan combine; tsan is mutually exclusive with asan.
    local SANS=""
    [ "$ENABLE_ASAN" = true ] && SANS="address"
    [ "$ENABLE_UBSAN" = true ] && SANS="${SANS:+$SANS,}undefined"
    [ "$ENABLE_TSAN" = true ] && SANS="${SANS:+$SANS,}thread"
    if [ "$ENABLE_TSAN" = true ] && [ "$ENABLE_ASAN" = true ]; then
        echo "Error: --tsan and --asan are mutually exclusive." >&2; exit 1
    fi
    [ -n "$SANS" ] && EXTRA_ARGS="-DCMAKE_CXX_FLAGS=-fsanitize=$SANS -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=$SANS"
    [ -n "$SANS" ] && echo "  sanitizers: $SANS"

    local MARCH="x86-64-v3"
    [ "$ENABLE_NATIVE" = true ] && MARCH="native"

    echo "Configuring ${CAMEL} (-march=${MARCH})..."
    cmake -S . -B "$BUILD_DIR" \
        -DCMAKE_BUILD_TYPE="${CAMEL}" \
        -DHYLE_MARCH="${MARCH}" \
        $EXTRA_ARGS

    echo "Building ${CAMEL}..."
    cmake --build "$BUILD_DIR" --parallel "$(nproc)"
    echo "OK ${CAMEL} build complete."
}

TARGET="debug"; CAMEL_TARGET="Debug"; ACTION="build"
RUN_ALL_TESTS=false; DO_CLEAN=false
declare -a REQ_EXE=() REQ_SUITE=()
ENABLE_ASAN=false; ENABLE_UBSAN=false; ENABLE_TSAN=false; ENABLE_NATIVE=false; DO_DEEP_CLEAN=false

ARGS=("$@"); i=0
while [ $i -lt ${#ARGS[@]} ]; do
    arg="${ARGS[$i]}"; LOWER_ARG=$(echo "$arg" | tr '[:upper:]' '[:lower:]')
    case "$LOWER_ARG" in
        --help|-h) print_help; exit 0 ;;
        --test) RUN_ALL_TESTS=true ;;
        --clean) DO_CLEAN=true ;;
        --native) ENABLE_NATIVE=true ;;
        --asan) ENABLE_ASAN=true ;;
        --ubsan) ENABLE_UBSAN=true ;;
        --tsan) ENABLE_TSAN=true ;;
        --rm) DO_DEEP_CLEAN=true ;;
        clean) ACTION="soft_clean_all" ;;
        rm) ACTION="deep_clean" ;;
        package) ACTION="package" ;;
        release) TARGET="release"; CAMEL_TARGET="Release" ;;
        relwithdebinfo) TARGET="relwithdebinfo"; CAMEL_TARGET="RelWithDebInfo" ;;
        minsizerel) TARGET="minsizerel"; CAMEL_TARGET="MinSizeRel" ;;
        debug) TARGET="debug"; CAMEL_TARGET="Debug" ;;
        --*)
            # An unrecognized switch is a request to run the test executable of that
            # name (resolved against the build tree). An optional following token is a
            # Boost suite filter.
            name="${arg#--}"; suite=""
            next_i=$((i + 1))
            if [ $next_i -lt ${#ARGS[@]} ]; then
                case "${ARGS[$next_i]}" in
                    --*|debug|release|relwithdebinfo|minsizerel|clean|rm|package) ;;
                    *) suite="${ARGS[$next_i]}"; i=$next_i ;;
                esac
            fi
            REQ_EXE+=("$name"); REQ_SUITE+=("$suite") ;;
        *) echo "Error: invalid argument '$arg'." >&2; exit 1 ;;
    esac
    i=$((i + 1))
done

case "$ACTION" in
    deep_clean) deep_clean_project; exit 0 ;;
    soft_clean_all) soft_clean_project; exit 0 ;;
    package)
        VER="0.0.0"
        echo "Building release for packaging..."
        build_one_config release Release
        STAGE=$(mktemp -d); PKG="morphe-${VER}"; mkdir -p "$STAGE/$PKG"
        cp build/release/morphe "$STAGE/$PKG/"
        [ -f LICENSE ] && cp LICENSE "$STAGE/$PKG/"
        cat > "$STAGE/$PKG/config.example" <<CFG
# morphe node config: one "key value" per line.
block_pace_ms 1000
listen_port 40000
rpc_port 41000
admin_token CHANGE_ME
CFG
        cat > "$STAGE/$PKG/README.txt" <<'RD'
Morphe 0.0.0 - in-RAM BFT KV blockchain node (Hyle layer 3).

Quick start (single-node dev chain):
  ./morphe init myhome            # scaffold key + genesis + config
  ./morphe start myhome           # run (JSON logs to stdout)

Local testnet (4 nodes over loopback):
  ./morphe testnet 4 tn 40000
  ./morphe start tn/node0 & ./morphe start tn/node1 & ...

Operate (RPC on 127.0.0.1:rpc_port from config):
  ./morphe status  myhome
  ./morphe query   myhome balance <pubkey_hex>
  ./morphe tx      transfer myhome <to_pubkey> <amount> <seq>
  ./morphe gov     vote remove myhome <pubkey>
  ./morphe snapshot dump myhome state.snap
  ./morphe leave   myhome

Observability:  GET http://127.0.0.1:<rpc_port>/metrics  (Prometheus)
                GET http://127.0.0.1:<rpc_port>/health   (200 ready / 503 catching up)
RD
        tar -czf "morphe-${VER}.tar.gz" -C "$STAGE" "$PKG"
        rm -rf "$STAGE"
        echo "Wrote morphe-${VER}.tar.gz ($(du -h "morphe-${VER}.tar.gz" | cut -f1))"
        exit 0 ;;
    build)
        [ "$DO_DEEP_CLEAN" = true ] && deep_clean_project
        [ "$DO_CLEAN" = true ] && clean_one_target "$TARGET"
        build_one_config "$TARGET" "$CAMEL_TARGET"
        TESTS_DIR="build/${TARGET}/tests"
        fail=0
        if [ "$RUN_ALL_TESTS" = true ]; then
            mapfile -t all_exes < <(find "$TESTS_DIR" -maxdepth 1 -type f -executable -printf '%f\n' 2>/dev/null | sort)
            if [ ${#all_exes[@]} -eq 0 ]; then
                echo "No test executables in $TESTS_DIR." >&2; exit 1
            fi
            for e in "${all_exes[@]}"; do
                run_test_exe "$TESTS_DIR/$e" "$e" "" || fail=1
            done
        fi
        for idx in "${!REQ_EXE[@]}"; do
            e="${REQ_EXE[$idx]}"; s="${REQ_SUITE[$idx]}"
            if [ -x "$TESTS_DIR/$e" ]; then
                label="$e"; [ -n "$s" ] && label="$e ($s)"
                run_test_exe "$TESTS_DIR/$e" "$label" "$s" || fail=1
            else
                echo "Error: unknown switch '--$e' (no test executable '$e' in $TESTS_DIR)." >&2
                exit 1
            fi
        done
        if [ "$fail" -ne 0 ]; then exit 1; fi ;;
esac

echo ""; echo "Done."
