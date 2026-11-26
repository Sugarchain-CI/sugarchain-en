#requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Local')]
    [string] $PayloadPath,
    [Parameter(Mandatory, ParameterSetName = 'Lan')]
    [uri] $PayloadUri,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $ManifestSha256,
    [string] $PriorPython = 'C:\Users\ak\AppData\Local\Temp\sugarchain-en8-proof-4170b8c033\python\python.exe',
    [string] $PythonArchive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$baselineSource = '8cae65e954ee78a1b40879c968ef2049d170930e'
$baselineTree = 'a9b417f9093256338b09e095c42f8cb114040a65'
$candidateSource = '9c502574b652804905d2533d51742ca91f694532'
$candidateTree = 'f44aa1b47f9701996046bbb396106f1d5c365e66'
$baselineBinaries = @{
    msvcrt = 'b0a10dc30299a2fac0f4426f6d195a639afac2dfa73cefecbc25b86e1ce0d00b'
    ucrt = '64ceba489eeffce7acce3c6ec92996b5f47cc63fd347b14fdaeacdb580ecdecf'
}
$archiveSha = '91d828c2da3a029b41699e918674a0cb379c02cf20dab9c501306885f837402a'
$headerArchive = 'mainnet-headers-100k.bin.gz'
$screenSha = '035be5c48d0a540a2eebd9d6121350eacd719ac099e7bc9d88205a27983d0cff'
$headerSha = '1d6b46da12f732190804a276b0c457d3c0ff923733ba29294f826eea971664ce'
$crts = @('msvcrt', 'ucrt')
$packageFiles = @('SHA256SUMS.release-inputs', 'release-source-sha.txt', 'release-source-tree.txt', 'bin/sugarchaind.exe')
$files = @($headerArchive, 'overlap/presync-overlap-paired.py', 'overlap/mainnet_paired.py',
    'overlap/mainnet_probe.py', 'overlap/presync_sweep.py')
foreach ($role in @('baseline', 'candidate')) {
    foreach ($crt in $crts) {
        foreach ($file in $packageFiles) {
            $files += "$role/$crt/$file"
        }
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    -not [Environment]::Is64BitOperatingSystem) {
    throw 'This procedure requires native Windows x86-64.'
}
if ($PSCmdlet.ParameterSetName -eq 'Lan') {
    if (-not $PayloadUri.IsAbsoluteUri -or $PayloadUri.Scheme -notin @('http','https') -or
        $PayloadUri.UserInfo -or $PayloadUri.Query -or $PayloadUri.Fragment -or
        -not $PayloadUri.AbsoluteUri.EndsWith('/')) {
        throw 'Use an HTTP(S) LAN directory URL ending in / without a credential, query or fragment.'
    }
}

$temp = Join-Path $env:LOCALAPPDATA 'Temp'
$owned = Join-Path $temp ('sugarchain-en8-native-pairs-' + [guid]::NewGuid().ToString('N').Substring(0,12))
New-Item -ItemType Directory -Path $owned | Out-Null
$payload = Join-Path $owned 'payload'
$output = Join-Path $owned 'results'
New-Item -ItemType Directory -Path @($payload, $output) | Out-Null
Write-Output "Owned run: $owned"

function Assert-Digest {
    param([string] $FilePath, [string] $Expected, [string] $Label)
    $hash = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $Expected.ToLowerInvariant()) {
        throw "SHA-256 mismatch for $Label"
    }
    return $hash
}

function Copy-PayloadFile {
    param([string] $RelativePath)
    $dest = Join-Path $payload ($RelativePath.Replace('/', '\'))
    $parent = Split-Path -Parent $dest
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    if ($PayloadPath) {
        Copy-Item -LiteralPath (Join-Path $PayloadPath ($RelativePath.Replace('/', '\'))) -Destination $dest
    } else {
        $uri = [uri]::new($PayloadUri, $RelativePath)
        Invoke-WebRequest -UseBasicParsing -Uri $uri -MaximumRedirection 0 -TimeoutSec 20 -OutFile $dest
    }
    return $dest
}

function Test-ReleaseInput {
    param([string] $Package, [string] $Source, [string] $Tree, [string] $KnownBinary)
    $manifest = Join-Path $Package 'SHA256SUMS.release-inputs'
    $items = @{}
    foreach ($name in $packageFiles[1..3]) {
        $pattern = '^(?<sha>[0-9a-f]{64}) [ *]' + [regex]::Escape($name) + '$'
        $lines = @(Get-Content -LiteralPath $manifest -Encoding UTF8 | Where-Object { $_ -cmatch $pattern })
        if ($lines.Count -ne 1) { throw "Expected exactly one original package checksum for $name" }
        $item = Join-Path $Package ($name.Replace('/', '\'))
        $items[$name] = Assert-Digest $item ($lines[0].Substring(0,64)) $item
    }
    if ((Get-Content -LiteralPath (Join-Path $Package 'release-source-sha.txt') -Raw).Trim() -cne $Source -or
        (Get-Content -LiteralPath (Join-Path $Package 'release-source-tree.txt') -Raw).Trim() -cne $Tree) {
        throw "Unexpected source or tree in $Package"
    }
    if ($KnownBinary -and $items['bin/sugarchaind.exe'] -cne $KnownBinary) {
        throw "Unexpected baseline daemon in $Package"
    }
    return $items['bin/sugarchaind.exe']
}

try {
    $manifestPath = Copy-PayloadFile 'manifest.json'
    $null = Assert-Digest $manifestPath $ManifestSha256 'transport manifest'
    $manifest = Get-Content -LiteralPath $manifestPath -Encoding UTF8 -Raw | ConvertFrom-Json
    $entries = @($manifest.files.PSObject.Properties)
    if ($entries.Count -ne $files.Count) { throw 'Unexpected transport manifest file count.' }
    foreach ($entry in $entries) {
        if ($entry.Name -cnotin $files -or $entry.Value -cnotmatch '^[0-9a-f]{64}$') {
            throw "Unexpected entry in transport manifest: $($entry.Name)"
        }
    }
    foreach ($file in $files) {
        $entry = $manifest.files.PSObject.Properties[$file]
        if ($null -eq $entry) { throw "Missing transport checksum for $file" }
        $null = Assert-Digest (Copy-PayloadFile $file) $entry.Value $file
    }
    $null = Assert-Digest (Join-Path $payload $headerArchive) $headerSha $headerArchive

    $screen = Join-Path $payload 'overlap\presync-overlap-paired.py'
    $null = Assert-Digest $screen $screenSha 'corrected overlap helper'

    $inputs = [ordered]@{}
    foreach ($crt in $crts) {
        $base = Test-ReleaseInput (Join-Path $payload "baseline\$crt") $baselineSource $baselineTree ($baselineBinaries[$crt])
        $cand = Test-ReleaseInput (Join-Path $payload "candidate\$crt") $candidateSource $candidateTree ''
        if ($base -ceq $cand) { throw "Expected distinct $crt daemon binaries" }
        $inputs[$crt] = [ordered]@{ baseline_sha256 = $base; candidate_sha256 = $cand }
    }

    if (-not $PythonArchive) {
        $PythonArchive = Join-Path (Split-Path -Parent (Split-Path -Parent $PriorPython)) 'python.zip'
    }
    $null = Assert-Digest $PythonArchive $archiveSha 'retained CPython 3.13.9 archive'
    $runtime = Join-Path $owned 'python'
    Expand-Archive -LiteralPath $PythonArchive -DestinationPath $runtime
    $python = Join-Path $runtime 'python.exe'
    $signature = Get-AuthenticodeSignature -LiteralPath $python
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notlike '*Python Software Foundation*') {
        throw "CPython Authenticode verification failed: $($signature.Status)"
    }
    if (Test-Path -LiteralPath $PriorPython -PathType Leaf) {
        $priorHash = (Get-FileHash -LiteralPath $PriorPython -Algorithm SHA256).Hash
        $null = Assert-Digest $python $priorHash 'retained interpreter match'
    }
    $pythonVersion = & $python -B -c 'import struct,sys; assert sys.version_info[:3] == (3,13,9) and struct.calcsize(chr(80)) == 8; print(sys.version.split()[0])'
    if ($LASTEXITCODE -ne 0) { throw 'CPython 3.13.9 x64 version check failed.' }

    $launcher = Join-Path $owned 'launch-owned.py'
    @'
from contextlib import redirect_stderr, redirect_stdout
import ctypes
from ctypes import wintypes
from pathlib import Path
import subprocess
import sys
import time
import traceback
from urllib.request import ProxyHandler, build_opener, install_opener

script, log, budget, *args = sys.argv[1:]
with open(log, "w", encoding="utf-8") as output, redirect_stdout(output), redirect_stderr(output):
    try:
        script = Path(script).resolve(strict=True)
        deadline = time.monotonic() + int(budget)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.SetPriorityClass.restype = wintypes.BOOL
        if not kernel.SetPriorityClass(kernel.GetCurrentProcess(), subprocess.BELOW_NORMAL_PRIORITY_CLASS):
            raise ctypes.WinError(ctypes.get_last_error())
        install_opener(build_opener(ProxyHandler({})))
        sys.path.insert(0, str(script.parent))
        import mainnet_probe

        class OwnedSubprocess:
            CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS

            def __getattr__(self, name):
                return getattr(subprocess, name)

        mainnet_probe.subprocess = OwnedSubprocess()
        source = script.read_text(encoding="utf-8")
        original = "deadline = time.monotonic() + 240"
        accept_limit = "listener.settimeout(30)"
        if source.count(original) != 1 or source.count(accept_limit) != 1 or '"Shutdown done" not in log' not in source:
            raise RuntimeError("Unexpected overlap runner, listener timeout or shutdown marker")
        bounded = "deadline = min(time.monotonic() + 95, OWNED_DEADLINE)"
        bounded_accept = (
            "seconds_left = OWNED_DEADLINE - time.monotonic()\n"
            "        if seconds_left <= 0:\n"
            "            raise TimeoutError('Owned Windows comparison budget expired')\n"
            "        listener.settimeout(min(30, seconds_left))"
        )
        source = source.replace(original, bounded).replace(accept_limit, bounded_accept)
        code = compile(source, str(script), "exec")
        sys.argv = [str(script), *args]
        exec(code, {"__name__": "__main__", "__file__": str(script), "OWNED_DEADLINE": deadline})
    except Exception:
        traceback.print_exc()
        sys.exit(1)
'@ | Set-Content -LiteralPath $launcher -Encoding ASCII

    $hostMetadata = [ordered]@{
        baseline_source = $baselineSource
        baseline_tree = $baselineTree
        candidate_source = $candidateSource
        candidate_tree = $candidateTree
        processor = $env:PROCESSOR_IDENTIFIER
        logical_cpus = [Environment]::ProcessorCount
        physical_cpu = @(Get-CimInstance -ClassName Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors)
        os = [Environment]::OSVersion.VersionString
        python = $pythonVersion
        inputs = $inputs
        priority = 'BelowNormal'
        header_archive_sha256 = $headerSha
        presync_helper_sha256 = $screenSha
        controlled_delivery_delay_seconds = 0.200
        manifest_sha256 = $ManifestSha256.ToLowerInvariant()
    }
    $hostMetadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $output 'inputs.json') -Encoding UTF8
    $timer = [Diagnostics.Stopwatch]::StartNew()
    foreach ($crt in $crts) {
        $budget = 540 - [int][Math]::Ceiling($timer.Elapsed.TotalSeconds)
        if ($budget -lt 90) { throw "Insufficient remaining benchmark budget for $crt" }
        $log = Join-Path $output "$crt.log"
        Write-Output "Starting $crt 40,000-header native comparison."
        & $python -B $launcher $screen $log $budget `
            --baseline (Join-Path $payload "baseline\$crt\bin\sugarchaind.exe") `
            --candidate (Join-Path $payload "candidate\$crt\bin\sugarchaind.exe") `
            --headers (Join-Path $payload $headerArchive) --case-root (Join-Path $owned "cases\$crt") `
            --output (Join-Path $output "$crt.json") --lead-marker 'PRESYNC lead committed:'
        if ($LASTEXITCODE -ne 0) { throw "$crt comparison failed. See $log" }
    }
    Write-Output "Completed physical Windows comparisons. Results: $output"
} catch {
    Write-Output "Comparison stopped. Preserved diagnostics: $output"
    throw
}
