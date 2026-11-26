#!/usr/bin/env bash
set -euo pipefail

target=${1:?Linux release target required}
root=${2:?Fresh isolated output directory required}
audit=${3:?Audit script and fixture directory required}
seconds=${MAINNET_NETWORK_SECONDS:-75}

case "$target" in
    x86_64-linux-gnu)
        host=x86_64
        machine='Advanced Micro Devices X86-64'
        hash=607a37de6c2567fe0b8da96393419e001ef68f88acb363d840701b97b6bdf83c ;;
    aarch64-linux-gnu)
        host=aarch64
        machine=AArch64
        hash=03daa74e0d6baae4d6b6b8f3df2b7b0e3a348448fe6778af9816c183d6609f22 ;;
    arm-linux-gnueabihf)
        host=$(uname -m)
        [[ $host == aarch64 || $host == armv7l || $host == armv8l ]]
        machine=ARM
        hash=ff756cf340c7a2f5f6aaf8ce6fc7e009169277e58a67d38878bbe1a395ae673a ;;
    *) exit 2 ;;
esac
[[ $(uname -s) == Linux && $(uname -m) == "$host" ]]

mkdir -p "$(dirname "$root")"
mkdir "$root"
root=$(realpath "$root")
audit=$(realpath "$audit")
mkdir -p "$root/results" "$root/settings/config" "$root/settings/cache" "$root/settings/data"

if [[ $target == arm-linux-gnueabihf && $host == aarch64 ]]; then
    python3 "$audit/check-native-armhf.py" "$root/results/armhf-native.json"
fi

stem="sugarchain-en-31.1.2-$target"
asset="$stem.tar.gz"
if [[ -n ${EN7_ARCHIVE_DIR:-} ]]; then
    cp -- "$EN7_ARCHIVE_DIR/$asset" "$root/$asset"
else
    curl --fail --silent --show-error --location --retry 2 --max-time 90 \
        --output "$root/$asset" "https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.7/$asset"
fi
printf '%s  %s\n' "$hash" "$asset" > "$root/results/archive.sha256"
(cd "$root" && sha256sum --check results/archive.sha256)
tar -xzf "$root/$asset" -C "$root"

export XDG_CONFIG_HOME="$root/settings/config"
export XDG_CACHE_HOME="$root/settings/cache"
export XDG_DATA_HOME="$root/settings/data"
unset QT_QPA_PLATFORM WAYLAND_DISPLAY FONTCONFIG_FILE FONTCONFIG_PATH
export LC_ALL=C

{
    echo "Target: $target"
    echo "Host: $(uname -smr)"
    lscpu | awk -F: '/^Architecture:|^CPU\(s\):|^Model name:|^CPU part:|^Hypervisor vendor:|^Virtualization type:/{print}'
} > "$root/results/host.txt"

failed=0
for component in daemon gui; do
    launcher=(python3)
    extra=()
    receiver="$root/$stem/bin/sugarchaind"
    if [[ $component == gui ]]; then
        launcher=(xvfb-run -a -s '-screen 0 1280x800x24' env QT_QPA_PLATFORM=xcb python3)
        extra=(--gui)
        receiver="$root/$stem/bin/sugarchain-qt"
    fi
    [[ -x "$receiver" ]]
    actual=$(readelf -h "$receiver" | awk -F: '/Machine:/{sub(/^[[:space:]]+/, "", $2); print $2}')
    [[ $actual == "$machine" ]]
    (cd "$(dirname "$receiver")" && sha256sum "$(basename "$receiver")") >> "$root/results/executables.sha256"

    # Keep each application's settings and benchmark nodes separate.
    for setting_dir in "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"; do
        mkdir -p "$setting_dir/$component"
    done
    if XDG_CONFIG_HOME="$XDG_CONFIG_HOME/$component" XDG_CACHE_HOME="$XDG_CACHE_HOME/$component" \
       XDG_DATA_HOME="$XDG_DATA_HOME/$component" \
       "${launcher[@]}" "$audit/mainnet_probe.py" \
         --binary "$receiver" \
         --output "$root/results/$component.json" \
         --fixture "$audit/mainnet-blocks.dat.gz" \
         --fixture-info "$audit/fixture.json" \
         --network-seconds "$seconds" "${extra[@]}" > "$root/results/$component.log" 2>&1; then
        printf 'Completed %s %s\n' "$target" "$component"
    else
        printf 'Failed %s %s. See the attached log.\n' "$target" "$component" >&2
        failed=1
    fi
done
exit "$failed"
