#!/usr/bin/env python3
"""Validate pinned diagnostic inputs and record bounded cross-build evidence."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.check_output(['git', '-c', 'safe.directory=' + str(root), '-C', str(root), *args], text=True).strip()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def main():
    mode, root_arg, assets_arg, output_arg, *extra = sys.argv[1:]
    root, assets, output = map(Path, (root_arg, assets_arg, output_arg))
    pins = json.loads((assets / 'pins.json').read_text())
    output.mkdir(parents=True, exist_ok=True)
    assert git(root, 'rev-parse', 'HEAD') == pins['source_commit']
    assert git(root, 'rev-parse', 'HEAD^{tree}') == pins['source_tree']
    patch = assets / 'intel-exact-package-profile.patch'
    assert digest(patch) == pins['profile_patch_sha256']
    assert digest(assets / 'regtest-sync.py') == pins['benchmark_sha256']
    if mode == 'prepare':
        assert not git(root, 'diff', '--name-only')
        subprocess.run(['git', '-C', str(root), 'apply', '--check', str(patch)], check=True)
        hook = '\npython3 "${BASE_READ_ONLY_DIR}/.diagnostic-inputs/.github/diagnostics/intel-cross-profile/build-variants.py" "${BASE_ROOT_DIR}" "${BASE_READ_ONLY_DIR}/.diagnostic-inputs/.github/diagnostics/intel-cross-profile" "${BASE_BUILD_DIR}"\n'
        runner = root / 'ci/test/03_test_script.sh'
        runner.write_text(runner.read_text() + hook)
        save(output / 'source.json', {**pins, 'diagnostic_only': True,
             'ci_only_metadata_hook_sha256': hashlib.sha256(hook.encode()).hexdigest(),
             'initial_daemon_source_unmodified': not git(root, 'diff', '--name-only', '--', 'src')})
        print('Verified pinned source, unapplied profile patch and unmodified benchmark helper.')
        return
    assert mode == 'collect' and len(extra) == 2
    variant = extra[1]
    assert variant in ('default', 'o3', 'profile')
    build = Path(extra[0])
    database = json.loads((build / 'compile_commands.json').read_text())
    wanted = {'validation.cpp', 'net.cpp', 'net_processing.cpp', 'scheduler.cpp',
              'txmempool.cpp', 'streams.cpp', 'blockstorage.cpp', 'yespower-opt.c'}
    entries = []
    for row in database:
        if Path(row['file']).name not in wanted:
            continue
        args = row.get('arguments') or shlex.split(row['command'])
        levels = [a for a in args if re.fullmatch(r'-O(?:[0-9]|s|z|g|fast)?', a)]
        assert levels and levels[-1] == '-O3', row['file']
        assert any(a in ('-flto', '-flto=thin', '-flto=full') for a in args), row['file']
        assert any(a in ('-mmacos-version-min=14.0', '-mmacosx-version-min=14.0') for a in args), row['file']
        assert not any(a in ('-march=native', '-mcpu=native', '-mtune=native') or
                       re.match(r'-march=x86-64-v[234]$', a) for a in args), row['file']
        entries.append({'source': row['file'], 'arguments': args})
    assert wanted <= {Path(e['source']).name for e in entries}
    compiler_files = list((build / 'CMakeFiles').glob('*/CMakeCXXCompiler.cmake'))
    assert len(compiler_files) == 1
    compiler = compiler_files[0].read_text()
    version = re.search(r'set\(CMAKE_CXX_COMPILER_VERSION "([^"]+)"\)', compiler).group(1)
    compiler_id = re.search(r'set\(CMAKE_CXX_COMPILER_ID "([^"]+)"\)', compiler).group(1)
    assert compiler_id == 'Clang' and version.startswith('19.'), (compiler_id, version)
    cache = {}
    for line in (build / 'CMakeCache.txt').read_text().splitlines():
        if line and not line.startswith(('#', '//')) and ':' in line and '=' in line:
            key, value = line.split('=', 1)
            cache[key.split(':', 1)[0]] = value
    expected = {'CMAKE_BUILD_TYPE': 'Release', 'CMAKE_C_FLAGS_RELEASE': '-O3',
                'CMAKE_CXX_FLAGS_RELEASE': '-O3', 'CMAKE_INTERPROCEDURAL_OPTIMIZATION': 'ON',
                'BUILD_SHARED_LIBS': 'OFF', 'REDUCE_EXPORTS': 'ON', 'BUILD_DAEMON': 'ON',
                'BUILD_GUI': 'OFF', 'BUILD_TESTS': 'OFF', 'BUILD_CLI': 'OFF',
                'BUILD_TX': 'OFF', 'BUILD_UTIL': 'OFF', 'BUILD_WALLET_TOOL': 'OFF',
                'ENABLE_WALLET': 'ON', 'ENABLE_IPC': 'OFF', 'WITH_USDT': 'OFF'}
    for key, value in expected.items():
        assert cache.get(key) == value, (key, cache.get(key))
    headers = list(build.rglob('bitcoin-build-config.h'))
    assert len(headers) == 1
    header = headers[0].read_text()
    macros = dict(re.findall(r'^#define\s+(\w+)\s+([^\n]+)', header, re.M))
    assert macros.get('ENABLE_WALLET') == '1'
    assert macros.get('ENABLE_EXTERNAL_SIGNER') == '1'
    assert 'ENABLE_TRACING' not in macros
    assert 'USE_DBUS' not in macros and 'USE_QRCODE' not in macros
    consumers = {}
    for name in ('USE_QRCODE', 'USE_DBUS'):
        found = []
        for path in (root / 'src').rglob('*'):
            if path.suffix not in ('.cpp', '.h', '.c'):
                continue
            if re.search(r'\b' + name + r'\b', path.read_text(errors='replace')):
                rel = path.relative_to(root).as_posix()
                assert rel.startswith('src/qt/'), (name, rel)
                found.append(rel)
        assert found
        consumers[name] = sorted(found)
    template = (root / 'cmake/bitcoin-build-config.h.in').read_text()
    assert not re.search(r'\bBUILD_(GUI|TESTS|CLI|TX|UTIL|WALLET_TOOL)\b', template)
    # Record the actual daemon link command and driver expansion without relinking.
    if cache['CMAKE_GENERATOR'] == 'Ninja':
        commands = subprocess.check_output([cache['CMAKE_MAKE_PROGRAM'], '-C', str(build), '-t', 'commands', 'bitcoind'], text=True).splitlines()
        links = [c for c in commands if re.search(r'-o\s+(?:\S*/)?sugarchaind(?:\s|$)', c)]
    else:
        links = [p.read_text().strip() for p in build.rglob('bitcoind.dir/link.txt')]
    assert len(links) == 1, len(links)
    link = links[0]
    chunks = re.split(r'\s+&&\s+', link)
    driver = next(shlex.split(c) for c in chunks if re.search(r'-o\s+(?:\S*/)?sugarchaind(?:\s|$)', c))
    if driver and driver[0] == ':':
        driver = driver[1:]
    assert driver and 'clang' in Path(driver[0]).name, driver[:1]
    replay = subprocess.run([driver[0], '-###', *driver[1:]], cwd=build, text=True, capture_output=True)
    assert replay.returncode == 0, replay.stderr[-1000:]
    assert len(replay.stderr) < 131072
    linker_arguments = set(shlex.split(replay.stderr))
    explicit_o3 = {'--lto-O3', '--lto-CGO3'}
    if variant == 'default':
        assert not explicit_o3.intersection(linker_arguments), 'Default unexpectedly forwards explicit O3 linker options'
    else:
        assert explicit_o3 <= linker_arguments, 'O3 linker options were not forwarded to the actual linker'
    linker = next((token for token in shlex.split(replay.stderr) if Path(token).name == 'ld64.lld' and Path(token).is_file()), shutil.which('ld64.lld'))
    linker_version = subprocess.check_output([linker, '--version'], text=True).strip() if linker else None
    cxx_version = subprocess.check_output([driver[0], '--version'], text=True).splitlines()[0]
    save(output / 'compiler-flags.json', {
        'compiler_id': compiler_id, 'compiler_version': version, 'compiler_version_text': cxx_version,
        'linker_version': linker_version, 'daemon_link_command': link, 'driver_link_expansion': replay.stderr,
        'core_translation_units': entries,
        'cmake_options': {key: cache[key] for key in expected},
        'generated_header_sha256': digest(headers[0]), 'generated_macros': macros,
        'gui_only_macro_consumers': consumers,
        'feature_scope': 'GUI-only generated macros differ from the full package; their consumers are confined to src/qt. Target-only options have no generated-config macro. No full GUI configure was attempted without Qt.',
        'dependencies': 'Repository Darwin depends; NO_QT=1 excludes only Qt/QR/native-Qt package sets. Wallet and external signer settings remain enabled.',
    })
    daemon = build / 'bin/sugarchaind'
    assert daemon.is_file()
    shutil.copy2(daemon, output / 'sugarchaind')
    save(output / 'daemon.json', {'unsigned_sha256': digest(daemon), 'size_bytes': daemon.stat().st_size,
                                  'instrumented': variant == 'profile', 'variant': variant, 'source_tree': pins['source_tree']})
    delta = subprocess.check_output(['git', '-C', str(root), 'diff', '--binary', '--', 'src'])
    if variant != 'profile':
        assert not delta
    save(output / 'variant-source.json', {
        'variant': variant, 'source_commit': pins['source_commit'], 'source_tree': pins['source_tree'],
        'instrumented': variant == 'profile', 'tracked_daemon_diff_sha256': hashlib.sha256(delta).hexdigest(),
        'profile_headers': {str(p.relative_to(root)): digest(p) for p in
                            (root / 'src/util/netprofile.h', root / 'src/util/intel_stage_profile.h')} if variant == 'profile' else {},
        'executable_release_linker_flags': cache.get('CMAKE_EXE_LINKER_FLAGS_RELEASE', ''),
    })
    print(f'{variant}: Clang {version}, Release -O3/IPO, macOS14, generic x86_64 and feature scope verified.')


if __name__ == '__main__':
    main()
