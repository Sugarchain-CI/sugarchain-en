#!/usr/bin/env python3
"""Preserve a default build, relink identical bitcode, then build diagnostics."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def manifest(build):
    return {p.relative_to(build).as_posix(): digest(p) for p in sorted(build.rglob('*'))
            if p.is_file() and p.suffix in ('.o', '.a') and 'profile-transfer' not in p.parts}


def main():
    root, assets, build = map(Path, sys.argv[1:])
    transfer = build / 'profile-transfer'
    audit = assets / 'audit-build.py'
    def collect(variant):
        subprocess.run([sys.executable, str(audit), 'collect', str(root), str(assets),
                        str(transfer / variant), str(build), variant], check=True)
    def compile_daemon():
        subprocess.run(['cmake', '--build', str(build), '--target', 'bitcoind', '--parallel',
                        str(os.cpu_count() or 2)], check=True)
    collect('default')
    objects_before = manifest(build)
    commands_before = digest(build / 'compile_commands.json')
    assert objects_before
    old_flags = ''
    for line in (build / 'CMakeCache.txt').read_text().splitlines():
        if line.startswith('CMAKE_EXE_LINKER_FLAGS_RELEASE:'):
            old_flags = line.split('=', 1)[1]
    flags = (old_flags + ' -Wl,--lto-O3,--lto-CGO3').strip()
    subprocess.run(['cmake', '-S', str(root), '-B', str(build),
                    '-DCMAKE_EXE_LINKER_FLAGS_RELEASE=' + flags], check=True)
    assert digest(build / 'compile_commands.json') == commands_before
    compile_daemon()
    objects_after = manifest(build)
    assert objects_before == objects_after, 'Relink unexpectedly changed object/archive contents'
    assert digest(build / 'compile_commands.json') == commands_before
    collect('o3')
    object_hash = hashlib.sha256(json.dumps(objects_before, sort_keys=True).encode()).hexdigest()
    (transfer / 'relink.json').write_text(json.dumps({
        'same_object_and_archive_contents': True, 'object_and_archive_count': len(objects_before),
        'object_manifest_sha256': object_hash, 'compile_commands_sha256': commands_before,
        'prior_executable_release_linker_flags': old_flags, 'new_executable_release_linker_flags': flags,
        'default_daemon_sha256': digest(transfer / 'default/sugarchaind'),
        'o3_daemon_sha256': digest(transfer / 'o3/sugarchaind'),
    }, indent=2) + '\n')
    patch = assets / 'intel-exact-package-profile.patch'
    pins = json.loads((assets / 'pins.json').read_text())
    assert digest(patch) == pins['profile_patch_sha256']
    subprocess.run(['git', '-C', str(root), 'apply', '--check', str(patch)], check=True)
    subprocess.run(['git', '-C', str(root), 'apply', str(patch)], check=True)
    subprocess.run(['git', '-C', str(root), 'diff', '--check'], check=True)
    compile_daemon()
    collect('profile')
    print('Default and O3 bitcode manifests match; O3 diagnostic profile compiled separately.')


if __name__ == '__main__':
    main()
