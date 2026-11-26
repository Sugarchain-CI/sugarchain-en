# Physical Windows Mainnet presync comparison

Compare the previously checked Windows baseline with the Windows candidate containing the direct Win32 reader fix. Use build 45872110419's native Windows unit and package results, including the append regression, to establish readiness before running the physical comparison. Build 45866616248 is outside this comparison.

| Role | Actions run | Source | Tree |
| --- | --- | --- | --- |
| Baseline | [45841070388](https://github.com/Sugarchain-CI/sugarchain-en/actions/runs/45841070388) | `8cae65e954ee78a1b40879c968ef2049d170930e` | `a9b417f9093256338b09e095c42f8cb114040a65` |
| Candidate | [45872110419](https://github.com/Sugarchain-CI/sugarchain-en/actions/runs/45872110419) | `9c502574b652804905d2533d51742ca91f694532` | `f44aa1b47f9701996046bbb396106f1d5c365e66` |

## Stage the payload on Nana

Run from an owned artifact directory. The preparation script uses normal `gh run download` paths with exact run and artifact names. Both baseline packages are already available in the retained directory below. The default downloads the two candidate runtime artifacts once. If they have already been downloaded into exact artifact-name subdirectories, pass `--candidate-artifacts <directory>` to reuse them.

```bash
python3 -B /home/ak/.cache/codex-tmp/20261127T030437-b136d379e221/prepare-sumi-mainnet-payload.py \
  --overlay /home/ak/.cache/codex-tmp/20261126T230229-0ec345f58917/source/.github/en8-mainnet \
  --baseline-artifacts /home/ak/.cache/codex-tmp/20261126T160142-6036f6eca56e/presync-timeout-results \
  --downloads "$PWD/actions-downloads" \
  --output "$PWD/public-sumi-payload"
```

Keep the printed manifest digest independently. The script verifies every original package manifest entry, both source and tree IDs, the known baseline daemon identities, and the five fixture and helper digests. In particular, the corrected presync runner has SHA-256 `035be5c48d0a540a2eebd9d6121350eacd719ac099e7bc9d88205a27983d0cff` and expects the native shutdown message `Shutdown done`.

The payload contains 21 members named by `manifest.json`, plus the manifest itself.

```text
mainnet-headers-100k.bin.gz
overlap/{presync-overlap-paired,mainnet_paired,mainnet_probe,presync_sweep}.py
baseline/msvcrt/{SHA256SUMS.release-inputs,release-source-sha.txt,release-source-tree.txt,bin/sugarchaind.exe}
baseline/ucrt/{SHA256SUMS.release-inputs,release-source-sha.txt,release-source-tree.txt,bin/sugarchaind.exe}
candidate/msvcrt/{SHA256SUMS.release-inputs,release-source-sha.txt,release-source-tree.txt,bin/sugarchaind.exe}
candidate/ucrt/{SHA256SUMS.release-inputs,release-source-sha.txt,release-source-tree.txt,bin/sugarchaind.exe}
```

Transfer only this public payload and the launcher through the existing file path. Keep package caches, credentials, Actions object URLs, test executables and installation assets on the staging host.

## Run on Sumi after native verification

```powershell
powershell.exe -NoProfile -File C:\path\run-sumi-mainnet-pairs.ps1 `
  -PayloadPath C:\path\public-sumi-payload `
  -ManifestSha256 '<digest printed by the preparation step>'
```

An authorized temporary LAN directory can be supplied as `-PayloadUri 'http://<LAN-IP>:<port>/'` instead. The launcher starts no server and changes no firewall rules.

The default interpreter comes from the existing CPython 3.13.9 x64 embed archive at `C:\Users\ak\AppData\Local\Temp\sugarchain-en8-proof-4170b8c033\python.zip`. The launcher checks the archive checksum, extracts a fresh runtime, verifies its Python Software Foundation signature, and checks the exact interpreter version and process width. Pass `-PythonArchive` if the same checksum-pinned archive is staged at a different path.

Run MSVCRT before UCRT. Each comparison uses the stock Mainnet minimum chain work, a controlled 200 ms response delay, and 40,000 authentic Mainnet headers in baseline, candidate, candidate, baseline order. It verifies the full 100,000-header input digest and chain before selecting the prefix. The node states must remain at Mainnet genesis for both chain and indexed headers while the presync height advances. Native marker counts, process CPU, and clean shutdown are retained.

Each run starts one CLI fixture node at a time. Its datadir is under a new `%LOCALAPPDATA%\Temp\sugarchain-en8-native-pairs-<id>`, its wallet is disabled, and it uses an isolated loopback peer. Only the owned Python process and its fixture children run below normal priority. Earlier physical proof measurements suggest that both CRTs together should take approximately four to six minutes under light load. Transfer and runtime setup occur before the 540-second shared benchmark deadline. Internal waits and child cleanup remain bounded. The separate six-arm body reader comparison is outside this physical presync run.

Keep `results\inputs.json`, both CRT result files, and case logs. Compare matched pairs on the same CRT. The fixed loopback interval measures presync under controlled delivery delay and cannot establish complete Mainnet IBD time or public-peer throughput.
