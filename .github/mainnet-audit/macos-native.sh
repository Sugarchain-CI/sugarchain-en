#!/usr/bin/env bash
set -euo pipefail
umask 077

tools_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work_dir=${1:?Provide a new isolated macOS benchmark directory}
arch=${BENCH_ARCH:?Set BENCH_ARCH to arm64 or x86_64}
case "$arch" in
  arm64|x86_64) ;;
  *) printf 'Unsupported macOS architecture: %s\n' "$arch" >&2; exit 2 ;;
esac
test "$(uname -s)" = Darwin
test "$(uname -m)" = "$arch"
test "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0

mkdir "$work_dir"
work_dir=$(cd -- "$work_dir" && pwd)
packages="$work_dir/packages"
results="$work_dir/results"
mkdir "$packages" "$results" "$work_dir/scratch"
{
  sw_vers
  uname -sm
  /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  printf 'Runner: %s\nImage: %s\n' "${BENCH_RUNNER:-local}" "${ImageVersion:-unknown}"
} > "$results/macos-$arch-host.txt"

release_tag=v31.1.2-en.7
release_url="https://github.com/decryp2kanon/sugarchain-en/releases/download/$release_tag"
stem="sugarchain-en-31.1.2-macos-$arch"
cli_archive="$stem-cli.tar.gz"
gui_archive="$stem.zip"
pin_file="$tools_dir/macos-en7-SHA256SUMS"
for asset in "$cli_archive" "$gui_archive"; do
  digest=$(awk -v asset="$asset" '$2 == asset {print $1; found++} END {if (found != 1) exit 1}' "$pin_file")
  printf '%s  %s\n' "$digest" "$asset" >> "$results/macos-$arch-verified-archives.sha256"
  curl --connect-timeout 15 --max-time 90 --retry 2 --retry-max-time 120 -fsSL \
    "$release_url/$asset" -o "$packages/$asset"
done
(cd "$packages" && shasum -a 256 -c "$results/macos-$arch-verified-archives.sha256")
tar -xzf "$packages/$cli_archive" -C "$packages"
ditto -x -k "$packages/$gui_archive" "$packages"

cli="$packages/$stem-cli/bin/sugarchaind"
app="$packages/Sugarchain-Qt.app"
gui="$app/Contents/MacOS/Sugarchain-Qt"
for exe in "$cli" "$gui"; do
  test -x "$exe"
  test "$(lipo -archs "$exe")" = "$arch"
done
codesign --verify --strict "$cli"
codesign --verify --deep --strict "$app"

failed=0
for variant in cli gui; do
  case "$variant" in
    cli) archive="$cli_archive"; receiver="$cli" ;;
    gui) archive="$gui_archive"; receiver="$gui" ;;
  esac
  label="macos-$arch-$variant"
  digest=$(awk -v asset="$archive" '$2 == asset {print $1}' "$results/macos-$arch-verified-archives.sha256")
  receiver_digest=$(shasum -a 256 "$receiver" | awk '{print $1}')
  python3 - "$results/$label-package.json" "$release_tag" "$archive" "$digest" "$receiver_digest" "$arch" "$variant" <<'PY'
import json
from pathlib import Path
import sys

output, release, archive, archive_sha256, executable_sha256, architecture, variant = sys.argv[1:]
record = {
    "release": release,
    "archive": archive,
    "archive_sha256": archive_sha256,
    "executable_sha256": executable_sha256,
    "architecture": architecture,
    "variant": variant,
    "native": True,
    "codesign_verified": True,
}
Path(output).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
PY
  args=(--binary "$receiver" --output "$results/$label.json"
        --fixture "$tools_dir/mainnet-blocks.dat.gz" --fixture-info "$tools_dir/fixture.json"
        --network-seconds 75 --temp-root "$work_dir/scratch")
  if [[ "$variant" == gui ]]; then
    args+=(--gui)
  fi
  mkdir "$work_dir/home-$variant"
  if CFFIXED_USER_HOME="$work_dir/home-$variant" python3 "$tools_dir/mainnet_probe.py" "${args[@]}" \
       > "$results/$label.log" 2>&1 && test -s "$results/$label.json"; then
    printf '%s: results recorded\n' "$label"
  else
    printf '%s: probe failed; inspect the artifact log\n' "$label" >&2
    failed=1
  fi
done
exit "$failed"
