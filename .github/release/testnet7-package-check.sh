#!/usr/bin/env bash
set -euo pipefail

package=sugarchain-en-31.1.2-x86_64-linux-gnu
sandbox=$(mktemp -d "${RUNNER_TEMP:?}/testnet7.XXXXXX")
tar -xzf "out/$package.tar.gz" -C "$sandbox"
bin="$sandbox/$package/bin"

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
    cli=("$bin/sugarchain-cli" -testnet "-datadir=$profile/node")
    XDG_SESSION_TYPE="$session" "$bin/sugarchain-qt" -testnet "-datadir=$profile/node" \
        -server=1 -choosedatadir=0 -splash=0 -listen=0 -networkactive=0 -keypool=4 \
        > "$profile/qt.log" 2>&1 &
    qt_pid=$!
    trap 'kill "$qt_pid" 2>/dev/null || true' EXIT
    genesis=$(timeout 90 "${cli[@]}" -rpcwait -rpcwaittimeout=75 getblockhash 0)
    [[ "$genesis" == 14f06e88eec9b21214a1eb54eee3cc03ceaf78ead1b16e40d8a383a5ff3e5e24 ]]
    "${cli[@]}" createwallet font-check > /dev/null
    address=$("${cli[@]}" -rpcwallet=font-check getnewaddress '' bech32)
    [[ "$address" == tugar1q* ]]
    "${cli[@]}" stop > /dev/null
    wait "$qt_pid"
    trap - EXIT
    if grep -Ei 'Fontconfig (warning|error):|Could not find the Qt platform plugin' "$profile/qt.log"; then
        exit 1
    fi
done

export BITCOIND="$bin/sugarchaind" BITCOINCLI="$bin/sugarchain-cli"
python3 build/test/functional/test_runner.py -j 1 \
    --tmpdirprefix="$RUNNER_TEMP" --resultsfile=out/testnet7-results.csv feature_sugarchain_testnet.py
python3 - <<'PY'
import csv
with open('out/testnet7-results.csv', newline='') as results:
    outcomes = {row['test']: row['status'] for row in csv.DictReader(results)}
assert outcomes == {'feature_sugarchain_testnet.py': 'Passed', 'ALL': 'Passed'}, outcomes
PY
