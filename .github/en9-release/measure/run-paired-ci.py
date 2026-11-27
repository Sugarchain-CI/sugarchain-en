#!/usr/bin/env python3
"""Run fixed native release comparisons and retain bounded, data-free evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--platform', choices=('windows', 'macos'), required=True)
    parser.add_argument('--candidate-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--crt', choices=('ucrt', 'msvcrt'))
    args = parser.parse_args()
    tools = Path(__file__).resolve().parent
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = os.environ.get('PRODUCT_SOURCE') or os.environ.get('RELEASE_SOURCE')
    tree = os.environ.get('PRODUCT_TREE') or os.environ.get('RELEASE_TREE')
    assert source and tree
    started = time.monotonic()
    summary = {'source': source, 'tree': tree, 'platform': args.platform,
               'crt': args.crt, 'cases': [], 'status': 'failed'}
    try:
        pins = {'en8-regtest-presync.py': 'd712a428c7bf29cab49827daf60e85f5d7196b5bf82c56c888ab5b73c7c5d714',
                'regtest-normal.py': '51468909810221a6172aaf2e8d5b3c2d5debafaf81e64b7e8700ac6e2e2168bb',
                'regtest-release-paired.py': '4910cb3b9f5940132f9767ee9dad8aefea17133aaaca36ade4521839ae22b15c'}
        for name, expected in pins.items():
            assert digest(tools / name) == expected, f'Changed frozen helper: {name}'
        subprocess.run([sys.executable, '-B', str(tools / 'prepare.py'),
                        '--output', str(out / 'fixture')], check=True, timeout=90)
        command = [sys.executable, '-B', str(tools / 'prepare-paired-inputs.py'),
                   '--platform', args.platform, '--candidate-dir', str(args.candidate_dir.resolve()),
                   '--baseline-pins', str(tools / 'assets.json'),
                   '--candidate-source', source, '--candidate-tree', tree,
                   '--output', str(out / 'inputs')]
        if args.crt:
            command += ['--crt', args.crt]
        with (out / 'prepare-inputs.log').open('wb') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=600)
        for interface in ('cli', 'gui'):
            command = [sys.executable, '-B', str(tools / 'regtest-release-paired.py'),
                       '--manifest', str(out / 'inputs' / f'{interface}.json'),
                       '--common', str(tools / 'en8-regtest-presync.py'),
                       '--normal', str(tools / 'regtest-normal.py'),
                       '--resources', str(tools / 'resource_metrics.py'),
                       '--fixture', str(out / 'fixture' / 'regtest-100000.dat'),
                       '--fixture-info', str(out / 'fixture' / 'fixture-info.json'),
                       '--work-dir', str(out / interface),
                       '--candidate-source', source, '--candidate-tree', tree,
                       '--trial-seconds', '300', '--total-seconds', '2100']
            with (out / f'{interface}-run.log').open('wb') as log:
                result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=2200)
            summary['cases'].append({'interface': interface, 'returncode': result.returncode})
            print(interface, 'exit', result.returncode, flush=True)
        assert all(case['returncode'] == 0 for case in summary['cases']), 'Native comparison failed'
        summary['status'] = 'passed'
    except Exception as error:
        summary['error'] = f'{type(error).__name__}: {error}'
    finally:
        summary['elapsed_seconds'] = time.monotonic() - started
        (out / 'comparison-summary.json').write_text(json.dumps(summary, indent=2) + '\n')
        files = set(out.glob('*.log')) | {out / 'comparison-summary.json'}
        for interface in ('cli', 'gui'):
            directory = out / interface
            if directory.exists():
                files.update(p for p in directory.rglob('*') if p.is_file() and p.suffix in ('.json', '.log'))
            manifest = out / 'inputs' / f'{interface}.json'
            if manifest.exists():
                files.add(manifest)
        inventory = [{'path': str(p.relative_to(out)), 'bytes': p.stat().st_size, 'sha256': digest(p)}
                     for p in sorted(files)]
        (out / 'evidence-files.json').write_text(json.dumps(inventory, indent=2) + '\n')
        files.add(out / 'evidence-files.json')
        with tarfile.open(out / 'evidence.tar.gz', 'w:gz') as archive:
            for path in sorted(files):
                archive.add(path, arcname=str(path.relative_to(out)), recursive=False)
    return 0 if summary['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
