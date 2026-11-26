#!/usr/bin/env bash
set -euo pipefail
test "$(uname -m)" = arm64
test "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1
prefix=sugarchain-en-31.1.2-macos-arm64
base=$(pwd)
tools="$base/release-tools/.github/diagnostics/en7-native-sync"
root="$RUNNER_TEMP/en7-native-synchronization"
mkdir -p "$root/home" "$root/baseline-archives" "$root/baseline"
export CFFIXED_USER_HOME="$root/home"
test "$(shasum -a 256 "$tools/native-sync.py" | awk '{print $1}')" = d9dbf9c56e97f1eb2e06b1e185c622b07671368879e66976c844a411441eb4d4
test "$(shasum -a 256 "$tools/testnet7-fixture.json" | awk '{print $1}')" = 7ce81c9bafb6d66ae263eb7848cf0db4eebb5f54f52474adc3abbbb49f507f25
for file in "$prefix-cli.tar.gz" "$prefix.zip"; do
  curl --fail --location --retry 3 --output "$root/baseline-archives/$file" \
    "https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.6/$file"
done
(cd "$root/baseline-archives" && shasum -a 256 -c "$tools/baseline.sha256")
tar -xzf "$root/baseline-archives/$prefix-cli.tar.gz" -C "$root/baseline"
ditto -x -k "$root/baseline-archives/$prefix.zip" "$root/baseline"
codesign --verify --strict "$root/baseline/$prefix-cli/bin/sugarchaind"
codesign --verify --deep --strict "$root/baseline/Sugarchain-Qt.app"
python3 "$tools/package-benchmark.py" "$base" "$root" "$tools"
