# Native Windows same-host option screen

Use the exact signed En.10 UCRT portable daemon on a single standard native AMD64 Windows Server 2025 runner. It is a byte-identical En.9-origin runtime, source `409ea3ee5f1cdb03790ec2adf5e191031a28737f`. Authenticate the published En.10 cleartext OpenPGP checksum signature, the UCRT archive, and the selected PE32+ executable. No program, source or platform policy changes are involved.

The stock condition has no worker, DB-cache or block-file XOR command-line overrides on either node. Each comparison arm has one deliberately specified scope.

| Treatment | Sender options | Receiver options |
|---|---|---|
| Receiver XOR diagnostic | Release defaults | `-blocksxor=0` |
| Receiver proof workers | Release defaults | `-parpow=1` |
| Receiver script workers | Release defaults | `-par=1` |
| Receiver database cache | Release defaults | `-dbcache=256` |
| Sender XOR diagnostic | `-blocksxor=0` | Release defaults |
| Historical combined options | Four options above | Four options above |

The XOR changes apply only to disposable diagnostic profiles. The receiver proof-worker arm is a negative control for this SHA256d Regtest fixture. A distinct Mainnet Yespower proof implementation can respond differently.

## Frozen order and scoring

Run one required unscored warmup per configuration. Run three paired stock/treatment comparisons for each of the six treatments, in alternating AB/BA order with rotation of the treatment sequence across rounds. The immutable schedule contains seven warmups and 36 scored cases, 43 fresh profiles in total. A comparison requires all 43 case receipts to pass. A material repeated improvement requires three faster paired outcomes and a median paired reduction of at least the greater of 250 ms and 5% of the paired stock median. Other outcomes remain inconclusive for material improvement. Retain every case, including failures, without choosing favorable samples. [Frozen schedule](frozen-schedule.json)

The benchmark clocks begin before receiver process creation and end at the first pinned active height 100,000, full work and IBD-clear observation. Each case requires a positive in-progress PRESYNC observation, two exact-peer header passes, normal debug-off logs, the expected final tip, UTXO and level-4 VerifyDB, and clean exit of both owned nodes. The exact explicit sender and receiver options are checked against their raw logs. The authenticated fixture, its initial sender preparation, the post-completion verify/UTXO work and teardown are outside the interval. Fixed benchmark isolation, mock-time and Regtest consistency-walk choices are unchanged from the published-package comparison.

Receiver and sender process CPU and logical I/O counters are sampled at the startup boundary, first observed positive PRESYNC, first observed full header completion and completion. Report startup through headers, observed PRESYNC through full headers, and full headers through IBD clear. Their sample timestamps and capture cost are retained. The PRESYNC-to-full-headers sample includes remaining PRESYNC and REDOWNLOAD. The final interval measures the portion of body work after the first full-header observation, including RPC poll latency. Keep profilers outside every scored case.

The six-way comparison can localize option and role effects in this Regtest workload. The both-node historical configuration does not isolate an individual option. An improvement, phase cost or I/O change from this screen establishes no full Mainnet duration.

## Integration

Copy `.github/en11-windows-causal/screen-windows.py` and use the private workflow fragment under the single branch guard. Supply the unchanged En.10 common and Windows release modules from the previous benchmark tool tree, with their existing LF and binary checkout treatment. The script verifies pinned helper hashes and app package identity. Add LF checkout treatment for the new diagnostic path. The job keeps only receipts and exact log paths in `en11-windows-stock-causal`. Do not copy runtime directories or extracted binaries into the artifact.
