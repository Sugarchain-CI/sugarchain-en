#!/usr/bin/env bash
set -euo pipefail

arch=$1
helpers="$GITHUB_WORKSPACE/ci-tools/.github/en8-release/macos"
test "$(uname -s)" = Darwin
test "$(uname -m)" = "$arch"
test "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1
test "$(git rev-parse HEAD)" = "$RELEASE_SOURCE"
test "$(git rev-parse 'HEAD^{tree}')" = "$RELEASE_TREE"
git diff-index --quiet HEAD --

incoming="$RUNNER_TEMP/en8-macos-incoming"
work="$RUNNER_TEMP/en8-macos-work"
release="$RUNNER_TEMP/en8-macos-release"
prefix="sugarchain-en-31.1.2-macos-$arch"
mkdir "$work" "$release" "$work/staged" "$work/checked"
python3 -B "$helpers/receipt.py" verify-cross "$incoming" "$arch"

native_program() {
  local exe=$1 dylibs
  test "$(lipo -archs "$exe")" = "$arch"
  dylibs=$(otool -L "$exe" | tail -n +2 | awk '{print $1}')
  test -n "$dylibs"
  if printf '%s\n' "$dylibs" | grep -Ev '^(/usr/lib/|/System/Library/)'; then
    echo "::error::Unexpected shared library in $exe"
    return 1
  fi
}

tar -xzf "$incoming/cli.tar.gz" -C "$work/staged"
mv "$work/staged/cli" "$work/staged/$prefix-cli"
ditto -x -k "$incoming/app.zip" "$work/staged"
app="$work/staged/Sugarchain-Qt.app"
test -f "$app/Contents/Resources/qt.conf"
cp COPYING contrib/debian/copyright "$app/Contents/Resources/"
native_program "$app/Contents/MacOS/Sugarchain-Qt"
for exe in "$work/staged/$prefix-cli/bin/"*; do
  native_program "$exe"
  strip -S "$exe"
  codesign --force --sign - --timestamp=none "$exe"
done
codesign --force --sign - --timestamp=none "$app"
ditto -c -k --norsrc --keepParent "$app" "$release/$prefix.zip"
COPYFILE_DISABLE=1 tar -czf "$release/$prefix-cli.tar.gz" -C "$work/staged" "$prefix-cli"

# Reopen the distribution bytes. Run the original tests against those binaries.
ditto -x -k "$release/$prefix.zip" "$work/checked"
tar -xzf "$release/$prefix-cli.tar.gz" -C "$work/checked"
python3 -B contrib/macdeploy/verify_bundle.py "$release/$prefix.zip" "$arch"
app="$work/checked/Sugarchain-Qt.app"
gui="$app/Contents/MacOS/Sugarchain-Qt"
cli_package="$work/checked/$prefix-cli"
bin="$cli_package/bin"
codesign --verify --deep --strict "$app"
for exe in "$bin/"*; do codesign --verify --strict "$exe"; done

unit="$work/test_bitcoin"
install -m755 "$incoming/test_bitcoin" "$unit"
native_program "$unit"
codesign --force --sign - --timestamp=none "$unit"
codesign --verify --strict "$unit"
suites=net_tests,peerman_tests,pow_tests,header_pow_tests,headers_sync_chainwork_tests,caches_tests,blockmanager_tests
"$unit" --run_test="$suites" --catch_system_error=no --log_level=test_suite --report_level=short \
  > "$work/native-tests.log" 2>&1
"$unit" --run_test=crypto_tests/yespower_golden_vectors,sha256_testvectors \
  --catch_system_error=no --log_level=test_suite --report_level=short >> "$work/native-tests.log" 2>&1
python3 -B "$helpers/run-header-pow.py" --source "$GITHUB_WORKSPACE" --package "$cli_package" \
  --work "$work/protocol" --arch "$arch"

python3 -B .github/ci-native-datadir.py --daemon "$bin/sugarchaind" --gui "$gui" --cli "$bin/sugarchain-cli" \
  --workdir "$work/native-datadir" > "$work/native-datadir.log" 2>&1
python3 -B "$helpers/smoke.py" --source "$GITHUB_WORKSPACE" --bindir "$bin" --gui "$gui" \
  --work "$work/runtime" > "$work/native-runtime.log" 2>&1
python3 -B "$helpers/receipt.py" finalize "$release" "$arch" --work "$work" --incoming "$incoming"
