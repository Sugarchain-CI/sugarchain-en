#!/usr/bin/env bash
set -euo pipefail
source_dir=${1:?Exact baseline checkout}
patch=${2:?Combined candidate patch}
work=${3:?New work directory}
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
test "$(git -C "$source_dir" rev-parse HEAD)" = 8400a011d8d4879fb606d50c263b6e4801213605
git -C "$source_dir" diff --exit-code
mkdir -p "$work/evidence" "$work/home"
export CFFIXED_USER_HOME="$work/home"
export CCACHE_DIR="$RUNNER_TEMP/macos-subsecond-ccache"
export HOMEBREW_NO_AUTO_UPDATE=1
for dependency in boost libevent ccache qt; do
  if [[ -z "$(brew list --versions "$dependency" 2>/dev/null || :)" ]]; then
    brew install "$dependency"
  fi
done
{
  sw_vers
  uname -sm
  sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  xcrun clang++ --version
  brew list --versions boost libevent ccache qt
  git -C "$source_dir" rev-parse HEAD HEAD^{tree}
  shasum -a 256 "$patch" "$here/native-sync.py" "$here/testnet7-fixture.json"
} > "$work/evidence/environment.txt"
cmake -S "$source_dir" -B "$work/build" -G Ninja \
  -DCMAKE_C_COMPILER=/usr/bin/clang -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS=-Werror=thread-safety \
  "-DCMAKE_PREFIX_PATH=$(brew --prefix boost);$(brew --prefix libevent);$(brew --prefix qt)" \
  -DCMAKE_CXX_FLAGS_RELEASE=-O3 -DCMAKE_C_FLAGS_RELEASE=-O3 \
  -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DBUILD_SHARED_LIBS=OFF -DREDUCE_EXPORTS=ON \
  -DBUILD_GUI=ON -DBUILD_GUI_TESTS=OFF -DBUILD_TESTS=OFF -DBUILD_BENCH=OFF \
  -DBUILD_FUZZ_BINARY=OFF -DBUILD_CLI=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF \
  -DBUILD_WALLET_TOOL=OFF -DENABLE_WALLET=ON -DENABLE_IPC=OFF -DWITH_USDT=OFF
git -C "$source_dir" show HEAD:src/crypto/yespower-1.0.1/yespower-opt.c > "$here/reference-yespower-opt.c"
python3 "$here/prepare-differential.py" "$here/testnet7-fixture.json" "$here/headers.txt"
for mode in baseline candidate; do
  if [[ "$mode" == candidate ]]; then
    git -C "$source_dir" apply "$patch"
    bash "$here/run-differential.sh" "$source_dir" "$work/differential" > "$work/evidence/differential.log" 2>&1
  fi
  cmake --build "$work/build" --target bitcoind bitcoin-qt --parallel "$(sysctl -n hw.logicalcpu)"
  mkdir -p "$work/$mode"
  for exe in sugarchaind sugarchain-qt; do
    install -m755 "$work/build/bin/$exe" "$work/$mode/$exe"
    codesign --force --sign - --timestamp=none "$work/$mode/$exe"
    codesign --verify --strict "$work/$mode/$exe"
    test "$(lipo -archs "$work/$mode/$exe")" = arm64
    shasum -a 256 "$work/$mode/$exe" >> "$work/evidence/binaries.sha256"
  done
done
cp "$work/build/CMakeCache.txt" "$work/evidence/"
cp "$work/build/compile_commands.json" "$work/evidence/"
git -C "$source_dir" diff --binary > "$work/evidence/applied.patch"
for sender in baseline candidate; do
  for mode in baseline candidate; do
    for kind in cli gui; do
      exe="$work/$mode/sugarchaind"
      extra=()
      if [[ "$kind" == gui ]]; then exe="$work/$mode/sugarchain-qt"; extra+=(--gui); fi
      label="$sender-sender-$mode-$kind"
      python3 "$here/native-sync.py" --sender "$work/$sender/sugarchaind" --receiver "$exe" \
        --work-dir "$work/$label" --platform macos --arch arm64 --network testnet7 \
        --fixture "$here/testnet7-fixture.json" "${extra[@]}" > "$work/evidence/$label.log" 2>&1
      cp "$work/$label/result.json" "$work/evidence/$label.json"
    done
  done
done
python3 - "$work/evidence" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); rows = {}
for path in sorted(p.glob('*-sender-*.json')):
    d = json.loads(path.read_text()); rows[path.stem] = d['median_sync_seconds']
    print(f'{path.stem}: {d["median_sync_seconds"]:.6f} s')
(p / 'summary.json').write_text(json.dumps(rows, indent=2) + '\n')
PY
# This separate verbose run is evidence only, not a scored sample.
for mode in baseline candidate; do
  label="trace-$mode"
  python3 "$here/trace-sync.py" --sender "$work/baseline/sugarchaind" \
    --receiver "$work/$mode/sugarchaind" --work-dir "$work/$label" \
    --platform macos --arch arm64 --network testnet7 --fixture "$here/testnet7-fixture.json" \
    > "$work/evidence/$label.log" 2>&1
  for repeat in 1 2 3; do
    cp "$work/$label/receiver-$repeat/testnet7/debug.log" "$work/evidence/$label-$repeat-debug.log"
  done
done
