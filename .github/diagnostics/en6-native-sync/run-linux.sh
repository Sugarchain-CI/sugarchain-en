#!/usr/bin/env bash
set -euo pipefail

target=${1:?Linux target triple required}
audit_dir=$(dirname "$(realpath "$0")")
output=${2:?isolated output directory required}
case "$target" in
    x86_64-linux-gnu) host=x86_64; arch=x86_64 ;;
    aarch64-linux-gnu) host=aarch64; arch=arm64 ;;
    arm-linux-gnueabihf) host=armv7l; arch=armhf ;;
    powerpc64-linux-gnu) host=ppc64; arch=ppc64 ;;
    riscv64-linux-gnu) host=riscv64; arch=riscv64 ;;
    *) exit 2 ;;
esac
[[ $(uname -m) == "$host" ]]
mkdir -p "$output" "$output/settings/config" "$output/settings/cache" "$output/results"
output=$(realpath "$output")
asset="sugarchain-en-31.1.2-$target.tar.gz"
hash=$(python3 - "$audit_dir/en6-runtime-hashes.json" "$asset" <<'PY'
import json, sys
from pathlib import Path
print(json.loads(Path(sys.argv[1]).read_text())[sys.argv[2]])
PY
)
if [[ -n ${EN6_ARCHIVE_DIR:-} ]]; then
    cp "$EN6_ARCHIVE_DIR/$asset" "$output/$asset"
else
    curl -fsSL --retry 3 --max-time 180 --output "$output/$asset" "https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.6/$asset"
fi
printf '%s  %s\n' "$hash" "$output/$asset" | sha256sum -c -
tar -xzf "$output/$asset" -C "$output"
stem=${asset%.tar.gz}
daemon="$output/$stem/bin/sugarchaind"
gui="$output/$stem/bin/sugarchain-qt"
export XDG_CONFIG_HOME="$output/settings/config"
export XDG_CACHE_HOME="$output/settings/cache"
export XDG_DATA_HOME="$output/settings/data"
unset QT_QPA_PLATFORM FONTCONFIG_FILE FONTCONFIG_PATH

failed=0
for component in daemon gui; do
    flags=()
    receiver=$daemon
    launcher=(python3)
    if [[ $component == gui ]]; then
        receiver=$gui
        flags=(--gui)
        launcher=(xvfb-run -a -s '-screen 0 1280x800x24' python3)
    fi
    for network in regtest testnet7; do
        fixture=()
        if [[ $network == testnet7 ]]; then fixture=(--fixture "$audit_dir/testnet7-fixture.json"); fi
        work="$output/$component-$network"
        log="$output/results/$component-$network.log"
        if "${launcher[@]}" "$audit_dir/native-sync.py" --sender "$daemon" --receiver "$receiver" --work-dir "$work" --platform linux --arch "$arch" --network "$network" --archive-sha256 "$hash" "${fixture[@]}" "${flags[@]}" > "$log" 2>&1; then
            cp "$work/result.json" "$output/results/$component-$network.json"
            printf 'PASS %s %s %s\n' "$target" "$component" "$network"
        else
            printf 'FAIL %s %s %s\n' "$target" "$component" "$network" >&2
            tail -n 20 "$log" >&2
            failed=1
        fi
    done
done
exit "$failed"
