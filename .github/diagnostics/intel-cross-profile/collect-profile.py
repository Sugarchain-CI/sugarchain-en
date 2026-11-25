#!/usr/bin/env python3
"""Validate the original package and retain bounded diagnostic evidence."""
import hashlib
import json
import platform
from pathlib import Path
import shutil
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    mode, assets_arg, *args = sys.argv[1:]
    assets = Path(assets_arg)
    pins = json.loads((assets / 'pins.json').read_text())
    assert digest(assets / 'regtest-sync.py') == pins['benchmark_sha256']
    if mode == 'verify':
        incoming, package = map(Path, args)
        assert digest(package / pins['original_archive']) == pins['original_archive_sha256']
        assert (package / 'release-source-sha.txt').read_text().strip() == pins['source_commit']
        assert (package / 'release-source-tree.txt').read_text().strip() == pins['source_tree']
        original = json.loads((package / 'regtest-benchmark.json').read_text())
        assert original['variants']['candidate']['binary_sha256'] == pins['original_daemon_sha256']
        source = json.loads((incoming / 'source.json').read_text())
        for key, value in pins.items():
            assert source[key] == value, key
        for variant in ('default', 'o3', 'profile'):
            daemon = json.loads((incoming / variant / 'daemon.json').read_text())
            assert daemon['instrumented'] == (variant == 'profile')
            assert daemon['variant'] == variant
            assert daemon['unsigned_sha256'] == digest(incoming / variant / 'sugarchaind')
        relink = json.loads((incoming / 'relink.json').read_text())
        assert relink['same_object_and_archive_contents']
        print('Original signed En6 archive, source identity, daemon metadata and profile inputs verified.')
        return
    if mode == 'binaries':
        baseline, binaries = map(Path, args)
        assert digest(baseline) == pins['original_daemon_sha256']
        for variant in ('default', 'o3', 'profile'):
            exe = binaries / variant / 'sugarchaind'
            libraries = subprocess.check_output(['otool', '-L', str(exe)], text=True).splitlines()[1:]
            assert libraries
            assert all(line.strip().split(' ', 1)[0].startswith(('/usr/lib/', '/System/Library/')) for line in libraries)
            build_commands = subprocess.check_output(['otool', '-l', str(exe)], text=True)
            assert 'minos 14.0' in build_commands or 'version 14.0' in build_commands
        print('Pinned original and three signed x86_64/macOS14 variants verified; system-only dylibs.')
        return
    assert mode == 'results'
    runs, output, binaries = map(Path, args)
    hashes = {variant: digest(binaries / variant / 'sugarchaind') for variant in ('default', 'o3', 'profile')}
    hashes['original'] = pins['original_daemon_sha256']
    expected = {'default-sender': ('default', 'o3', 'baseline', 3),
                'o3-sender': ('default', 'o3', 'candidate', 3),
                'profile': ('o3', 'profile', 'baseline', 1),
                'original-reference': ('original', 'default', 'baseline', 1)}
    output.mkdir(parents=True, exist_ok=True)
    for name, (baseline, candidate, sender, repeats) in expected.items():
        result = json.loads((runs / name / 'result.json').read_text())
        assert result['blocks'] == 10000 and result['sender_variant'] == sender
        assert result['sender_binary_sha256'] == hashes[baseline if sender == 'baseline' else candidate]
        for key in ('fixture_sha256', 'fixture_utxo_sha256', 'fixture_tip'):
            assert result[key] == pins[key], (name, key)
        assert result['variants']['baseline']['binary_sha256'] == hashes[baseline]
        assert result['variants']['candidate']['binary_sha256'] == hashes[candidate]
        for variant in result['variants'].values():
            assert len(variant['samples']) == repeats and all(sample['reload_verified'] for sample in variant['samples'])
        shutil.copyfile(runs / name / 'result.json', output / f'{name}.json')
    work = runs / 'profile'
    logs = {}
    for name in ('sender', 'baseline-1', 'candidate-1'):
        source = work / name / 'regtest/debug.log'
        selected, matched, kept = [], 0, 0
        with source.open(errors='replace') as stream:
            for line in stream:
                if not any(marker in line for marker in ('STAGEPROFILE', 'NATIVEFILE', 'NETPROFILE')):
                    continue
                matched += 1
                size = len(line.encode())
                if kept + size <= 262144 and len(selected) < 1500:
                    selected.append(line)
                    kept += size
        (output / f'{name}-profile.txt').write_text(''.join(selected))
        logs[name] = {'matching_lines': matched, 'retained_lines': len(selected),
                      'retained_bytes': kept, 'truncated': matched != len(selected)}
    assert logs['candidate-1']['matching_lines'] > 0
    def sysctl(key):
        proc = subprocess.run(['sysctl', '-n', key], text=True, capture_output=True)
        return proc.stdout.strip() if proc.returncode == 0 else None
    metadata = {'diagnostic_only': True, 'not_release_or_target_proof': True,
                'original_run_id': pins['original_run_id'], 'source_tree': pins['source_tree'],
                'profile_patch_sha256': pins['profile_patch_sha256'], 'benchmark_sha256': pins['benchmark_sha256'],
                'platform': platform.platform(), 'machine': platform.machine(),
                'cpu_brand': sysctl('machdep.cpu.brand_string'), 'physical_cpus': sysctl('hw.physicalcpu'),
                'logical_cpus': sysctl('hw.logicalcpu'), 'memory_bytes': sysctl('hw.memsize'),
                'signed_variant_sha256': hashes, 'logs': logs,
                'timing_scope': 'default-sender and o3-sender are uninstrumented three-repeat relink comparisons; profile and original-reference are one-repeat diagnostics only'}
    (output / 'diagnostic.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print('Relink comparisons and separate diagnostics retained; all exact fixtures and restart/UTXO checks passed.')


if __name__ == '__main__':
    main()
