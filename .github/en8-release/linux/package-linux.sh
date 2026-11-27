#!/usr/bin/env bash
# Package the pinned product checkout on an isolated Linux runner.
set -euo pipefail
export LC_ALL=C

host=${RELEASE_HOST:?}
mode=${RELEASE_MODE:?}
tools=$(cd -- "$(dirname -- "$0")" && pwd)
[[ $(git rev-parse HEAD) == "${SOURCE_REVISION:?}" ]]
[[ $(git rev-parse 'HEAD^{tree}') == "${SOURCE_TREE:?}" ]]
git diff --quiet HEAD --

case "$host/$mode" in
    x86_64-linux-gnu/native) machine='Advanced Micro Devices X86-64'; endian=little; bits=64 ;;
    aarch64-linux-gnu/native) machine=AArch64; endian=little; bits=64 ;;
    arm-linux-gnueabihf/cross) machine=ARM; endian=little; bits=32 ;;
    riscv64-linux-gnu/cross) machine=RISC-V; endian=little; bits=64 ;;
    powerpc64-linux-gnu/cross) machine=PowerPC64; endian=big; bits=64 ;;
    *) echo "Unexpected package target $host/$mode" >&2; exit 1 ;;
esac

jobs=$(nproc)
if (( jobs > 4 )); then jobs=4; fi
depends_host=$host
if [[ "$mode" == native ]]; then
    depends_host=$(cd depends && ./config.guess)
    [[ ${depends_host%%-*} == "${host%%-*}" ]]
fi
prefix="$PWD/depends/$depends_host"
tests=OFF
if [[ "$host" == x86_64-linux-gnu ]]; then tests=ON; fi
mkdir -p out/checks
make -C depends -j"$jobs" HOST="$depends_host" NO_IPC=1 2>&1 | tee out/checks/depends.log
cmake -S . -B build -G Ninja --toolchain "$prefix/toolchain.cmake" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_GUI=ON -DENABLE_WALLET=ON -DENABLE_IPC=OFF \
    -DBUILD_TESTS="$tests" -DBUILD_GUI_TESTS=OFF -DBUILD_TX=ON -DBUILD_UTIL=ON \
    -DBUILD_WALLET_TOOL=ON -DBUILD_BENCH=OFF -DBUILD_FUZZ_BINARY=OFF -DINSTALL_MAN=ON \
    '-DCMAKE_INSTALL_RPATH=$ORIGIN/../lib' \
    '-DCMAKE_EXE_LINKER_FLAGS=-static-libgcc -static-libstdc++ -Wl,--disable-new-dtags' \
    2>&1 | tee out/checks/configure.log
cmake --build build --parallel "$jobs" 2>&1 | tee out/checks/build.log

package="sugarchain-en-31.1.2-$host"
stage="$PWD/stage/$package"
docs="$stage/share/doc/SugarchainEn"
mkdir -p "$stage"
cmake --install build --strip --prefix "$stage"
if [[ "$tests" == ON ]]; then
    # CMake stages its internal unit runner with a full install.
    rm -- "$stage/libexec/test_bitcoin"
    rmdir -- "$stage/libexec"
fi
install -m644 README.md doc/sugarchain-en-{linux-release,draft-release-notes}.md "$docs/"
install -m644 share/examples/sugarchain.conf "$stage/sugarchain.conf"
cp -R share/rpcauth "$stage/share/"

# The static Qt executable uses the pinned shared font backends and system fonts.
mkdir -p "$stage/lib"
for lib in libfreetype.so.6 libfontconfig.so.1; do
    install -m644 "$prefix/lib/$lib" "$stage/lib/$lib"
done
python3 "$tools/linux-notices.py" depends/sources "$docs/dependency-notices"

programs=(sugarchain sugarchaind sugarchain-cli sugarchain-qt sugarchain-tx sugarchain-util sugarchain-wallet)
[[ $(find "$stage/bin" -mindepth 1 -maxdepth 1 | wc -l) -eq ${#programs[@]} ]]
for program in "${programs[@]}"; do
    [[ -x "$stage/bin/$program" && -s "$stage/share/man/man1/$program.1" ]]
done
[[ -s "$docs/COPYING" && -s "$docs/copyright" ]]
[[ -s "$stage/share/applications/org.sugarchain.SugarchainEn.desktop" ]]
[[ -s "$stage/share/metainfo/org.sugarchain.SugarchainEn.metainfo.xml" ]]
compgen -G "$stage/share/icons/hicolor/*/apps/sugarchain.png" > /dev/null

binaries=("$stage"/bin/* "$stage"/lib/*)
for lib in libatomic.so.1 libstdc++.so.6 libgcc_s.so.1; do
    if readelf -d "${binaries[@]}" | grep -F "[$lib]" > /dev/null; then
        runtime=$("$host-g++" -print-file-name="$lib")
        install -m644 "$runtime" "$stage/lib/$lib"
        binaries+=("$stage/lib/$lib")
        gcc_major=$("$host-g++" -dumpversion | cut -d. -f1)
        install -m644 "/usr/share/doc/gcc-$gcc_major-base/copyright" "$docs/dependency-notices/GCC-runtime-copyright"
    fi
done
report="$docs/linux-runtime.txt"
{
    echo "Sugarchain En 31.1.2 ($host)"
    echo "Release tag: $RELEASE_TAG"
    echo "Source: $SOURCE_REVISION"
    echo "Source tree: $SOURCE_TREE"
    echo "Build OS: $(. /etc/os-release && echo "$PRETTY_NAME")"
    "$host-g++" -dumpfullversion | sed 's/^/GCC: /'
    echo "Build: Release, wallet and static Qt, IPC disabled."
    if [[ "$mode" == native ]]; then
        echo "Runtime verification: native on $(uname -m)."
    else
        echo "Verification: cross-built ELF and package checks."
    fi
    echo "The GUI uses X11 or XWayland and the system's font configuration."
    echo "A matching Linux kernel and glibc are required. Each file's highest imported glibc version follows."
} > "$report"

for binary in "${binaries[@]}"; do
    header=$(readelf -h "$binary")
    grep -Eq "Machine: +$machine$" <<< "$header"
    grep -Fq "$endian endian" <<< "$header"
    grep -Eq "Class: +ELF$bits$" <<< "$header"
    if [[ "$host" == arm-linux-gnueabihf ]]; then
        grep -Fq 'hard-float ABI' <<< "$header"
    fi
    needed=$(readelf -d "$binary" | sed -n 's/.*(NEEDED).*\[\([^]]*\)\].*/\1/p')
    for lib in $needed; do
        case "$lib" in
            libc.so.6|libm.so.6|libdl.so.2|libpthread.so.0|librt.so.1|ld-linux*.so.*|ld64.so.1|libresolv.so.2) ;;
            *) [[ -f "$stage/lib/$lib" ]] || { echo "Missing library $lib for $binary" >&2; exit 1; } ;;
        esac
    done
    glibc=$(readelf -VW "$binary" | grep -oE 'GLIBC_[0-9.]*[0-9]' | sort -Vu | tail -1)
    printf '%s: %s; %s\n' "${binary#"$stage"/}" "$glibc" "$(xargs <<< "$needed")" >> "$report"
done
qt_dynamic=$(readelf -d "$stage/bin/sugarchain-qt")
grep -Fq 'Library rpath: [$ORIGIN/../lib]' <<< "$qt_dynamic"
for lib in libfontconfig.so.1 libfreetype.so.6; do
    grep -Fq "Shared library: [$lib]" <<< "$qt_dynamic"
done
cp -- "$report" out/checks/linux-runtime.txt

epoch=$(git show -s --format=%ct HEAD)
tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -C stage -cf - "$package" |
    gzip -n -9 > "out/$package.tar.gz"
(
    cd out
    sha256sum "$package.tar.gz" > package.sha256
    sha256sum --check --strict package.sha256
)
if [[ "$mode" == native ]]; then
    sandbox=$(mktemp -d "${RUNNER_TEMP:?}/en8-linux-check.XXXXXX")
    tar -xzf "out/$package.tar.gz" -C "$sandbox"
    timeout --signal=TERM --kill-after=10s 35m bash "$tools/verify-native.sh" \
        "$sandbox/$package/bin" "$PWD/out/checks" "$host"
fi
git diff --quiet HEAD --
git rev-parse HEAD > out/release-source-sha.txt
git rev-parse 'HEAD^{tree}' > out/release-source-tree.txt
python3 "$tools/record-provenance.py" "out/$package.tar.gz"
