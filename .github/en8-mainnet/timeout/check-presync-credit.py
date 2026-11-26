#!/usr/bin/env python3
"""Verify bounded local-proof credit through native Mainnet message processing."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import time
from mainnet_probe import node, rpc
from mainnet_paired import compact_size, hash256, message, version_payload, wait_for

GENESIS = '7d5eaec2dbb75f99feadfa524c78b7cabc1d8c8204f79d4f3a83381b811b0adc'
FIXTURE_SHA = 'f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd'
CREDIT = re.compile(r'PRESYNC proof time credit: peer=(\d+) granted_us=(\d+) remaining_us=(\d+) height=(\d+)')


def check_ledger(records):
    if [r['height'] for r in records] != [4000, 6000, 8000]:
        raise AssertionError('Credit must begin only after an established PRESYNC advances')
    budget = records[0]['granted_us'] + records[0]['remaining_us']
    remaining = budget
    peer = records[0]['peer']
    for row in records:
        if row['peer'] != peer or not 0 < row['granted_us'] <= remaining:
            raise AssertionError('Invalid per-peer local credit')
        remaining -= row['granted_us']
        if remaining != row['remaining_us']:
            raise AssertionError('Cumulative allowance changed or was replenished')
    return {'initial_allowance_us': budget, 'granted_us': budget - remaining, 'remaining_us': remaining}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--headers', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gui', action='store_true')
    args = parser.parse_args()
    args.binary = args.binary.resolve(strict=True)
    args.timeout = 120
    host = (platform.system(), platform.machine().lower())
    if host not in (('Darwin', 'arm64'), ('Windows', 'amd64'), ('Windows', 'x86_64')):
        raise RuntimeError('Requires a targeted native host')
    if args.gui and host[0] == 'Windows' and os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted':
        raise RuntimeError('GUI settings isolation requires the disposable hosted Windows account')
    raw = gzip.decompress(args.headers.read_bytes())
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA or len(raw) != 8_000_000:
        raise ValueError('Authentic Mainnet fixture mismatch')
    headers = [raw[i:i+80] for i in range(0, 8000 * 80, 80)]
    previous = bytes.fromhex(GENESIS)[::-1]
    for header in headers:
        if header[4:36] != previous:
            raise ValueError('Mainnet continuity mismatch')
        previous = hash256(header)
    args.output.mkdir(parents=True, exist_ok=False)
    data = args.output / 'node'
    report = {'status': 'running', 'host': host, 'gui': args.gui,
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
              'headers': 8000, 'fixture_sha256': FIXTURE_SHA, 'final_presync_hash': previous[::-1].hex()}
    destination = args.output / 'result.json'
    destination.write_text(json.dumps(report, indent=2) + '\n')
    try:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            listener.settimeout(args.timeout)
            peer_port = listener.getsockname()[1]
            flags = [f'-connect=127.0.0.1:{peer_port}', '-v2transport=0', '-dnsseed=0', '-fixedseeds=0',
                     '-dns=0', '-parpow=8', '-maxpowcache=16', '-assumevalid=0', '-debug=net']
            if args.gui and host[0] == 'Windows':
                flags.append('-resetguisettings')
            with node(args, data, 'presync', extra_flags=flags) as (proc, port, _):
                conn, _ = listener.accept()
                with conn:
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    deadline = time.monotonic() + args.timeout
                    wait_for(conn, b'version', deadline)
                    conn.sendall(message(b'version', version_payload(peer_port, starting_height=8000)) + message(b'verack', b''))
                    wait_for(conn, b'verack', deadline)
                    wait_for(conn, b'getheaders', deadline, locator=bytes.fromhex(GENESIS)[::-1])
                    for start in range(0, 8000, 2000):
                        batch = headers[start:start+2000]
                        conn.sendall(message(b'headers', compact_size(len(batch)) + b''.join(h + b'\0' for h in batch)))
                        wait_for(conn, b'getheaders', deadline, locator=hash256(batch[-1]))
                    state = rpc(data, port, 'getblockchaininfo')
                    peers = rpc(data, port, 'getpeerinfo')
                    if state['chain'] != 'main' or state['headers'] != 0 or state['blocks'] != 0 or len(peers) != 1 or peers[0].get('presynced_headers') != 8000:
                        raise AssertionError('Unexpected Mainnet PRESYNC state')
            if proc.returncode != 0:
                raise RuntimeError(f'Owned node did not exit cleanly: {proc.returncode}')
        records = [dict(zip(('peer', 'granted_us', 'remaining_us', 'height'), map(int, m.groups())))
                   for m in CREDIT.finditer((data/'debug.log').read_text(errors='replace'))]
        report.update(status='passed', credits=records, ledger=check_ledger(records), node_exit=proc.returncode)
    except Exception as error:
        report.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': report['status'], 'gui': args.gui, 'credits': len(records), 'ledger': report['ledger']}))


if __name__ == '__main__':
    main()
