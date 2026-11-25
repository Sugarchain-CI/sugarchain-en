#!/usr/bin/env bash
set -euo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=${1:?Provide an isolated benchmark directory}
arch=${BENCH_ARCH:?Set BENCH_ARCH to arm64 or x86_64}
case "$arch" in
  arm64|x86_64) ;;
  *) printf 'Unsupported macOS architecture: %s\n' "$arch" >&2; exit 2 ;;
esac
test "$(uname -s)" = Darwin
test "$(uname -m)" = "$arch"
test "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || printf 0)" = 0
test -f "$here/native-sync.py"
test -f "$here/testnet7-fixture.json"

mkdir "$work"
work=$(cd -- "$work" && pwd)
published="$work/published"
evidence="$work/evidence"
mkdir "$published" "$evidence" "$work/home"
export CFFIXED_USER_HOME="$work/home"
{
  sw_vers
  uname -sm
  /usr/sbin/sysctl machdep.cpu.brand_string hw.logicalcpu hw.memsize
  printf 'Runner %s\nImage %s\n' "${BENCH_RUNNER:-local}" "${ImageVersion:-unknown}"
} > "$evidence/host.txt"

stem="sugarchain-en-31.1.2-macos-$arch"
cli_archive="$stem-cli.tar.gz"
gui_archive="$stem.zip"
release_url=https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.6
for asset in "$cli_archive" "$gui_archive"; do
  curl --retry 4 --retry-all-errors --connect-timeout 20 --max-time 240 -fsSL \
    "$release_url/$asset" -o "$published/$asset"
  digest=$(awk -v asset="$asset" '$2 == asset { print $1; n++ } END { if (n != 1) exit 1 }' "$here/macos-SHA256SUMS")
  printf '%s  %s\n' "$digest" "$asset" >> "$evidence/verified-archive-sha256.txt"
done
(cd "$published" && shasum -a 256 -c "$evidence/verified-archive-sha256.txt")
tar -xzf "$published/$cli_archive" -C "$published"
ditto -x -k "$published/$gui_archive" "$published"

sender="$published/$stem-cli/bin/sugarchaind"
app="$published/Sugarchain-Qt.app"
gui="$app/Contents/MacOS/Sugarchain-Qt"
for exe in "$sender" "$gui"; do
  test -x "$exe"
  test "$(lipo -archs "$exe")" = "$arch"
  shasum -a 256 "$exe" >> "$evidence/macho-sha256.txt"
done
codesign --verify --strict "$sender"
codesign --verify --deep --strict "$app"

failed=0
for network in regtest testnet7; do
  for variant in cli gui; do
    case "$variant" in
      cli) archive="$cli_archive"; receiver="$sender" ;;
      gui) archive="$gui_archive"; receiver="$gui" ;;
    esac
    digest=$(awk -v asset="$archive" '$2 == asset {print $1}' "$evidence/verified-archive-sha256.txt")
    out="$work/$network-$variant"
    args=(--sender "$sender" --receiver "$receiver" --work-dir "$out"
          --platform macos --arch "$arch" --network "$network" --archive-sha256 "$digest")
    if [[ "$network" == testnet7 ]]; then
      args+=(--fixture "$here/testnet7-fixture.json")
    fi
    if [[ "$variant" == gui ]]; then
      args+=(--gui)
    fi
    if python3 "$here/native-sync.py" "${args[@]}" > "$evidence/$network-$variant.log" 2>&1 &&
       test -f "$out/result.json"; then
      cp "$out/result.json" "$evidence/$network-$variant.json"
      printf '%s %s: passed\n' "$network" "$variant"
    else
      printf '%s %s: failed, see benchmark evidence\n' "$network" "$variant" >&2
      failed=1
      if test -d "$out"; then
        find "$out" -name console.log -type f -exec sh -c '
          base=$1
          shift
          for file do
            printf "\n--- %s ---\n" "${file#"$base"/}"
            tail -c 4096 "$file"
          done
        ' macos-console "$out" {} + >> "$evidence/$network-$variant.log"
      fi
    fi
  done
done
exit "$failed"
