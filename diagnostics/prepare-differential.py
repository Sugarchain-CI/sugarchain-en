#!/usr/bin/env python3
"""Prepare immutable fixture headers and independently known genesis digests."""
import hashlib
import json
import pathlib
import struct
import sys

fixture = json.loads(pathlib.Path(sys.argv[1]).read_text())
rows = []
for label, merkle, timestamp, nonce, expected in (
    ('mainnet-genesis', '7677ce2a579cb0411d1c9e6b1e9072b8f537f1e59cb387dacac2daac56e150b0', 1565881200, 247, '0031205acedcc69a9c18f79b84790179d68fb90588bedee6587ff701bdde04eb'),
    ('testnet7-genesis', 'f224e997530c450804839e12d786b32485ee18997dcd00c31c10bf57e4ac22c6', 1795575600, 1320, '001c572d18bd3bda32894e8a13f3a0440a46d4eb62a24d31dd91bdd2f77545a4'),
):
    header = struct.pack('<I', 1) + bytes(32) + bytes.fromhex(merkle)[::-1] + struct.pack('<III', timestamp, 0x1f3fffff, nonce)
    rows.append((label, header.hex(), bytes.fromhex(expected)[::-1].hex()))
assert fixture['blocks'] == len(fixture['raw_blocks']) == 102
for i, block in enumerate(fixture['raw_blocks']):
    header = bytes.fromhex(block)[:80]
    assert hashlib.sha256(hashlib.sha256(header).digest()).digest()[::-1].hex() == fixture['block_hashes'][i]
    rows.append((f'testnet7-{i + 1}', header.hex(), '-'))
pathlib.Path(sys.argv[2]).write_text(''.join(' '.join(row) + '\n' for row in rows))
print(f'Prepared {len(rows)} immutable header vectors')
