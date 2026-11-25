#!/usr/bin/env bash
set -euo pipefail
assets="$GITHUB_WORKSPACE/.diagnostic-inputs/.github/diagnostics/intel-cross-profile"
python3 "$assets/audit-build.py" prepare "$GITHUB_WORKSPACE" "$assets" "$BASE_BUILD_DIR/profile-transfer"
source ./ci/test/00_setup_env.sh
export GOAL=all
export CCACHE_MAXSIZE=2G
export DEP_OPTS="${DEP_OPTS:-} NO_QT=1"
export BITCOIN_CONFIG="-DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE=-O3 -DCMAKE_CXX_FLAGS_RELEASE=-O3 -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_SHARED_LIBS=OFF -DREDUCE_EXPORTS=ON -DBUILD_DAEMON=ON -DBUILD_GUI=OFF -DENABLE_WALLET=ON -DENABLE_IPC=OFF -DBUILD_TESTS=OFF -DBUILD_GUI_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DBUILD_CLI=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DBUILD_WALLET_TOOL=OFF -DINSTALL_MAN=OFF -DWITH_USDT=OFF"
# Keep the repository's container/toolchain path; suppress its unbounded logs.
if python3 ./ci/test/02_run_container.py > "$RUNNER_TEMP/profile-build.log" 2>&1; then
  test -s "$BASE_BUILD_DIR/profile-transfer/profile/compiler-flags.json"
  test -x "$BASE_BUILD_DIR/profile-transfer/profile/sugarchaind"
  echo "Cross-profile daemon and compiler evidence collected inside the original toolchain container."
else
  status=$?
  tail -c 6000 "$RUNNER_TEMP/profile-build.log"
  exit "$status"
fi
