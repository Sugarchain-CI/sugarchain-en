#!/usr/bin/env bash
set -euo pipefail

arch=$1
test "$(git rev-parse HEAD)" = "$RELEASE_SOURCE"
test "$(git rev-parse 'HEAD^{tree}')" = "$RELEASE_TREE"
git diff-index --quiet HEAD --

source ./ci/test/00_setup_env.sh
test "$HOST" = "$arch-apple-darwin"
export GOAL="install deploy"
export BASE_OUTDIR="$BASE_BUILD_DIR/installed"
export BITCOIN_CONFIG="
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DREDUCE_EXPORTS=ON
  -DBUILD_GUI=ON -DENABLE_WALLET=ON -DENABLE_IPC=OFF
  -DBUILD_TESTS=ON -DBUILD_GUI_TESTS=OFF -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF
  -DBUILD_TX=ON -DBUILD_UTIL=ON -DBUILD_WALLET_TOOL=ON
  -DINSTALL_MAN=ON -DWITH_USDT=OFF"
if [[ "$arch" == arm64 ]]; then
  # Keep the Apple Silicon shipping profile from En.7.
  BITCOIN_CONFIG+=" -DCMAKE_C_FLAGS_RELEASE=-O3 -DCMAKE_CXX_FLAGS_RELEASE=-O3 -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON"
elif [[ "$arch" == x86_64 ]]; then
  # Restore the Intel profile shipped in En.6, with the default LTO link level.
  BITCOIN_CONFIG+=" -DCMAKE_C_FLAGS_RELEASE=-O3 -DCMAKE_CXX_FLAGS_RELEASE=-O3 -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON"
fi
# The container uses line-oriented environment variables.
BITCOIN_CONFIG=$(printf '%s\n' "$BITCOIN_CONFIG" | xargs)
python3 ./ci/test/02_run_container.py
if [[ "$arch" == x86_64 ]]; then
  python3 -B "$(dirname -- "${BASH_SOURCE[0]}")/verify-intel-codegen.py" "$BASE_BUILD_DIR"
fi

transfer="$RUNNER_TEMP/en9-macos-transfer"
scratch="$RUNNER_TEMP/en9-macos-transfer-cli"
mkdir "$transfer" "$scratch"
mkdir -p "$scratch/cli/bin" "$scratch/cli/share/man/man1"
cp "$(cat "$BASE_BUILD_DIR/macos-archive-path.txt")" "$transfer/app.zip"
python3 -B contrib/macdeploy/verify_bundle.py "$transfer/app.zip" "$arch"
for exe in sugarchain sugarchaind sugarchain-cli sugarchain-wallet sugarchain-tx sugarchain-util; do
  install -m755 "$BASE_BUILD_DIR/installed/bin/$exe" "$scratch/cli/bin/$exe"
  install -m644 "doc/man/$exe.1" "$scratch/cli/share/man/man1/$exe.1"
done
cp COPYING contrib/debian/copyright "$scratch/cli/"
tar -czf "$transfer/cli.tar.gz" -C "$scratch" cli
install -m755 "$BASE_BUILD_DIR/bin/test_bitcoin" "$transfer/test_bitcoin"
printf '%s\n' "$RELEASE_SOURCE" > "$transfer/release-source-sha.txt"
printf '%s\n' "$RELEASE_TREE" > "$transfer/release-source-tree.txt"
(
  cd "$transfer"
  sha256sum app.zip cli.tar.gz test_bitcoin release-source-sha.txt release-source-tree.txt > SHA256SUMS.cross-inputs
)
