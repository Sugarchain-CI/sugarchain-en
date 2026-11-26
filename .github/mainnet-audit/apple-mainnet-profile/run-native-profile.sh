#!/usr/bin/env bash
set -euo pipefail
umask 077

tool_dir=$(cd -- "$(dirname -- "$0")" && pwd)
root=${1:?Provide the new profile work directory}
test "$(uname -s)" = Darwin
test "$(uname -m)" = arm64
test "$(/usr/sbin/sysctl -in sysctl.proc_translated 2>/dev/null || printf 0)" != 1
mkdir "$root"
root=$(cd -- "$root" && pwd)
mkdir "$root/host" "$root/release"

record_sysctl() {
  local key=$1 value
  if value=$(/usr/sbin/sysctl -n "$key" 2>/dev/null); then
    printf '%s: %s\n' "$key" "$value"
  else
    printf '%s: unavailable\n' "$key"
  fi
}
{
  sw_vers
  for key in machdep.cpu.brand_string hw.logicalcpu hw.activecpu hw.cachelinesize hw.l1dcachesize \
             hw.l2cachesize hw.l3cachesize hw.nperflevels hw.memsize hw.pagesize; do
    record_sysctl "$key"
  done
  levels=$(/usr/sbin/sysctl -n hw.nperflevels 2>/dev/null || printf 0)
  if [[ $levels =~ ^[0-9]+$ ]] && (( levels <= 16 )); then
    for ((level = 0; level < levels; ++level)); do
      for key in name logicalcpu physicalcpu l2cachesize cpusperl2; do
        record_sysctl "hw.perflevel$level.$key"
      done
    done
  fi
  printf 'Runner image %s\n' "${ImageVersion:-unknown}"
} > "$root/host/topology.txt"

release=https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.7
stem=sugarchain-en-31.1.2-macos-arm64-cli
curl --fail --location --connect-timeout 15 --max-time 90 --retry 2 --retry-max-time 120 \
  --silent --show-error --output "$root/release/$stem.tar.gz" "$release/$stem.tar.gz"
(
  cd "$root/release"
  shasum -a 256 -c <<'PINS'
00433459749009dc5bc8f537c025797e690d3caf6cfcec4e1a7b5dbc54abed02  sugarchain-en-31.1.2-macos-arm64-cli.tar.gz
PINS
  tar -xzf "$stem.tar.gz"
)
cli="$root/release/$stem/bin/sugarchaind"
test "$(lipo -archs "$cli")" = arm64
codesign --verify --strict "$cli"
fixture_dir="$tool_dir/../apple-mainnet-sweep"
(
  cd "$fixture_dir"
  shasum -a 256 -c <<'PINS'
1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce  mainnet-headers-100k.bin.gz
PINS
)
python3 "$tool_dir/profile_released_node.py" \
  --binary "$cli" --binary-sha256 9509fc91b5c1f79b723257fd01056b3ed46fd10a19e85df99115f6fd9991cf26 \
  --headers "$fixture_dir/mainnet-headers-100k.bin.gz" \
  --headers-sha256 f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd \
  --fixture-tip b62290c6914adee9b29326b8a4567114fff1f9013acb9c3b6ff68612a2947f99 \
  --datadir "$root/fresh-profile-datadir" --results "$root/results"
