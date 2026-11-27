#!/usr/bin/env bash
# Verify extracted Linux packages on their native target.
set -euo pipefail

bindir=${1:?}
checks=${2:?}
host=${3:?}
sandbox=$(mktemp -d "${RUNNER_TEMP:?}/en8-linux-native.XXXXXX")
child=
cleanup() {
    if [[ -n "$child" ]]; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    fi
}
trap cleanup EXIT

export XDG_DATA_HOME="$sandbox/data" XDG_CONFIG_HOME="$sandbox/config" XDG_CACHE_HOME="$sandbox/cache"
export XDG_RUNTIME_DIR="$sandbox/run"
unset FONTCONFIG_FILE FONTCONFIG_PATH QT_QPA_PLATFORM
mkdir -m700 "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR" "$sandbox/node"

programs=(sugarchain sugarchaind sugarchain-cli sugarchain-qt sugarchain-tx sugarchain-util sugarchain-wallet)
for program in "${programs[@]}"; do
    args=(-version)
    case "$program" in
        sugarchain) args=(--version) ;;
        sugarchaind) args=("-datadir=$sandbox/node" -version) ;;
    esac
    timeout 90 "$bindir/$program" "${args[@]}" > "$sandbox/$program.version" 2>&1
    cat "$sandbox/$program.version" >> "$checks/native-versions.log"
    grep -Fq 'Sugarchain En' "$sandbox/$program.version"
done
for session in x11 wayland; do
    XDG_SESSION_TYPE="$session" timeout 90 "$bindir/sugarchain-qt" -version \
        > "$checks/qt-$session-version.log" 2> "$checks/qt-$session-stderr.log"
    grep -Fq "Sugarchain En" "$checks/qt-$session-version.log"
    if grep -Ei 'Fontconfig (warning|error):|Could not find the Qt platform plugin' "$checks/qt-$session-stderr.log"; then
        exit 1
    fi
done

cli=("$bindir/sugarchain-cli" "-datadir=$sandbox/node" -rpcport=26443)
"$bindir/sugarchaind" "-datadir=$sandbox/node" -rpcport=26443 -server=1 \
    -listen=0 -connect=0 -dnsseed=0 -discover=0 -networkactive=0 -maxconnections=0 -keypool=4 \
    > "$checks/native-daemon.log" 2>&1 &
child=$!
genesis=$(timeout 120 "${cli[@]}" -rpcwait -rpcwaittimeout=100 getblockhash 0)
[[ "$genesis" == 7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc ]]
"${cli[@]}" createwallet en_package_check > /dev/null
address=$("${cli[@]}" -rpcwallet=en_package_check getnewaddress '' bech32)
[[ "$address" == sugar1q* ]]
"${cli[@]}" stop > /dev/null
wait "$child"
child=
grep -Fq 'Shutdown done' "$checks/native-daemon.log"
printf '%s\n' "Mainnet genesis, wallet address prefix and clean shutdown passed." > "$checks/native-smoke.txt"

if [[ "$host" == x86_64-linux-gnu ]]; then
    for session in x11 wayland; do
        profile="$sandbox/$session"
        mkdir -m700 -p "$profile"/{data,config,cache,run,node}
        export XDG_DATA_HOME="$profile/data" XDG_CONFIG_HOME="$profile/config"
        export XDG_CACHE_HOME="$profile/cache" XDG_RUNTIME_DIR="$profile/run"
        unset FONTCONFIG_FILE FONTCONFIG_PATH QT_QPA_PLATFORM
        if [[ "$session" == wayland ]]; then
            cat > "$profile/fonts.conf" <<'XML'
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
<fontconfig>
  <description domain="fontconfig-conf">Test metadata</description>
  <include>/etc/fonts/fonts.conf</include>
</fontconfig>
XML
            export FONTCONFIG_FILE="$profile/fonts.conf"
        fi
        cli=("$bindir/sugarchain-cli" -testnet "-datadir=$profile/node" -rpcport=26444)
        XDG_SESSION_TYPE="$session" "$bindir/sugarchain-qt" -testnet "-datadir=$profile/node" -rpcport=26444 \
            -server=1 -choosedatadir=0 -splash=0 -listen=0 -networkactive=0 -keypool=4 \
            > "$checks/qt-$session-testnet7.log" 2>&1 &
        child=$!
        genesis=$(timeout 90 "${cli[@]}" -rpcwait -rpcwaittimeout=75 getblockhash 0)
        [[ "$genesis" == 14f06e88eec9b21214a1eb54eee3cc03ceaf78ead1b16e40d8a383a5ff3e5e24 ]]
        "${cli[@]}" createwallet font-check > /dev/null
        address=$("${cli[@]}" -rpcwallet=font-check getnewaddress '' bech32)
        [[ "$address" == tugar1q* ]]
        "${cli[@]}" stop > /dev/null
        wait "$child"
        child=
        if grep -Ei 'Fontconfig (warning|error):|Could not find the Qt platform plugin' "$checks/qt-$session-testnet7.log"; then
            exit 1
        fi
    done

    suites=net_tests,header_pow_tests,pow_tests,headers_sync_chainwork_tests,caches_tests,blockmanager_tests,peerman_tests
    timeout 1200 build/bin/test_bitcoin --run_test="$suites" --report_format=XML --report_level=detailed \
        --report_sink="$checks/focused-unit.xml" --log_level=message > "$checks/focused-unit.log" 2>&1
    timeout 120 build/bin/test_bitcoin --run_test=crypto_tests/yespower_golden_vectors,sha256_testvectors \
        --report_format=XML --report_level=detailed --report_sink="$checks/focused-crypto.xml" \
        --log_level=message > "$checks/focused-crypto.log" 2>&1
    python3 - "$checks" "$suites" <<'PY'
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

checks = Path(sys.argv[1])
units = ET.parse(checks / "focused-unit.xml")
expected = set(sys.argv[2].split(","))
performed = {row.get("name") for row in units.findall(".//TestSuite") if row.get("result") == "passed"}
assert expected <= performed, (expected, performed)
focus = [case for case in units.findall(".//TestCase") if case.get("name") == "mainnet_block_timeout_queued_body"]
assert len(focus) == 1 and focus[0].get("result") == "passed", "Queued Mainnet block timeout regression did not pass"
crypto = ET.parse(checks / "focused-crypto.xml")
performed = {case.get("name") for case in crypto.findall(".//TestCase") if case.get("result") == "passed"}
assert performed == {"yespower_golden_vectors", "sha256_testvectors"}, performed
PY
    export BITCOIND="$bindir/sugarchaind" BITCOINCLI="$bindir/sugarchain-cli"
    if timeout 600 python3 -B test/functional/p2p_sugarchain_header_pow.py --configfile="$PWD/build/test/config.ini" \
        --tmpdir="$sandbox/header-pow" --timeout-factor=8 --v1transport --nocleanup > "$checks/focused-p2p.log" 2>&1; then
        cp -- "$sandbox/header-pow/test_framework.log" "$checks/focused-p2p-framework.log"
    else
        if [[ -f "$sandbox/header-pow/test_framework.log" ]]; then
            cp -- "$sandbox/header-pow/test_framework.log" "$checks/focused-p2p-framework.log"
        fi
        exit 1
    fi
fi
