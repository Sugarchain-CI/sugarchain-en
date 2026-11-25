#!/usr/bin/env bash
set -euo pipefail
assets="$GITHUB_WORKSPACE/.diagnostic-inputs/.github/diagnostics/intel-cross-profile"
python3 "$assets/collect-profile.py" verify "$assets" "$GITHUB_WORKSPACE/incoming-profile" "$GITHUB_WORKSPACE/original-package"
archive="$GITHUB_WORKSPACE/original-package/sugarchain-en-31.1.2-macos-x86_64-cli.tar.gz"
mkdir -p "$RUNNER_TEMP/original-en6" "$RUNNER_TEMP/profile-binaries" "$RUNNER_TEMP/profile-runs" "$RUNNER_TEMP/profile-results"
tar -xzf "$archive" -C "$RUNNER_TEMP/original-en6"
original="$RUNNER_TEMP/original-en6/sugarchain-en-31.1.2-macos-x86_64-cli/bin"
test "$(uname -m)" = x86_64
for variant in default o3 profile; do
  mkdir "$RUNNER_TEMP/profile-binaries/$variant"
  exe="$RUNNER_TEMP/profile-binaries/$variant/sugarchaind"
  cp "incoming-profile/$variant/sugarchaind" "$exe"
  chmod 755 "$exe"
  test "$(lipo -archs "$exe")" = x86_64
  strip -S "$exe"
  codesign --force --sign - --timestamp=none "$exe"
  codesign --verify --strict "$exe"
done
codesign --verify --strict "$original/sugarchaind"
python3 "$assets/collect-profile.py" binaries "$assets" "$original/sugarchaind" "$RUNNER_TEMP/profile-binaries"
run_benchmark() {
  python3 "$assets/regtest-sync.py" --baseline-bin-dir "$1" --candidate-bin-dir "$2" --work-dir "$RUNNER_TEMP/profile-runs/$3" --sender "$4" --blocks 10000 --repeats "$5"
}
bins="$RUNNER_TEMP/profile-binaries"
run_benchmark "$bins/default" "$bins/o3" default-sender baseline 3
run_benchmark "$bins/default" "$bins/o3" o3-sender candidate 3
# Keep profile overhead and original-package equivalence outside the relink result.
run_benchmark "$bins/o3" "$bins/profile" profile baseline 1
run_benchmark "$original" "$bins/default" original-reference baseline 1
python3 "$assets/collect-profile.py" results "$assets" "$RUNNER_TEMP/profile-runs" "$RUNNER_TEMP/profile-results" "$bins"
