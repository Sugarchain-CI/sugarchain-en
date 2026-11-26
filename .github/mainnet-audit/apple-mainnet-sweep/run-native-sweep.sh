#!/usr/bin/env bash
set -euo pipefail
umask 077

tool_dir=$(cd -- "$(dirname -- "$0")" && pwd)
root=${1:?Provide the new benchmark work directory}
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || printf 0)" != 1
mkdir "$root"
root=$(cd -- "$root" && pwd)
mkdir "$root/release" "$root/results"
{
  sw_vers
  /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  printf 'Runner image %s\n' "${ImageVersion:-unknown}"
} > "$root/results/host.txt"

release=https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.7
stem=sugarchain-en-31.1.2-macos-arm64
for package in "$stem-cli.tar.gz" "$stem.zip"; do
  curl --fail --location --connect-timeout 15 --max-time 90 --retry 2 --retry-max-time 120 \
    --silent --show-error --output "$root/release/$package" "$release/$package"
done
(
  cd "$root/release"
  shasum -a 256 -c <<'PINS'
00433459749009dc5bc8f537c025797e690d3caf6cfcec4e1a7b5dbc54abed02  sugarchain-en-31.1.2-macos-arm64-cli.tar.gz
ffc7e054449a56a0229dc6f8222475f7c9d3c584b19c130c60d6e38ca98eb1ca  sugarchain-en-31.1.2-macos-arm64.zip
PINS
  tar -xzf "$stem-cli.tar.gz"
  ditto -x -k "$stem.zip" .
)
cli="$root/release/$stem-cli/bin/sugarchaind"
app="$root/release/Sugarchain-Qt.app"
gui="$app/Contents/MacOS/Sugarchain-Qt"
test "$(lipo -archs "$cli")" = arm64
test "$(lipo -archs "$gui")" = arm64
codesign --verify --strict "$cli"
codesign --verify --deep --strict "$app"
(
  cd "$tool_dir"
  shasum -a 256 -c <<'PINS'
1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce  mainnet-headers-100k.bin.gz
PINS
)
python3 "$tool_dir/presync_sweep.py" \
  --binary "$cli" --binary-sha256 9509fc91b5c1f79b723257fd01056b3ed46fd10a19e85df99115f6fd9991cf26 \
  --gui-binary "$gui" --gui-binary-sha256 931aef8251215e0b1628858192ebf22cb1e962fb63cf11cc44ba7602bdc24789 \
  --headers "$tool_dir/mainnet-headers-100k.bin.gz" \
  --headers-sha256 f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd \
  --fixture-tip b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99 \
  --work "$root/fresh-datadirs" --output "$root/results/native-mainnet-presync-sweep.json"
