# Intel Mac Mainnet request-ceiling screen

This diagnostic compares the two publicly released En.9 Intel macOS executables on one standard `macos-15-intel` runner. Each interface uses the same executable and options across arms except `-maxibdblocksinflight=16` versus `128`. No product binaries are rebuilt. The SHA-256 manifest is verified against the pinned public OpenPGP key, and its hashes, signed-mode archive contents, native Mach-O architecture and ad hoc code signatures are checked. Each running node must report the expected En.9 source version. [Public En.9 release](https://github.com/decryp2kanon/sugarchain-en/releases/tag/v31.1.2-en.9)

## Workload

The pinned fixture contains genuine Mainnet heights 1–4,096. Header preparation checks all 4,096 header submissions before timing. Four unprivileged, loopback-only peers announce the prepared tip and return only the requested, exact bodies. The only local admission override is `-minimumchainwork=0`. The ordinary maximum tip age, full proof and script checks, and `-assumevalid=0` remain in effect. Debug logging is disabled and checked through read-only RPCs at startup, end of delivery and reopening.

Body timing starts at the peers' tip announcements and ends at the first receiver RPC observation of all 4,096 active blocks. Header preparation, startup, UTXO scans, VerifyDB, shutdown and offline reopen are outside the time interval. Mainnet IBD must remain active at the historical endpoint and after reopening. The extra 0 ms or 100 ms is injected response delay, independent of the system's actual network RTT.

Every required case checks exact requested inventory and 1,286,835 body bytes, no cap violation, canonical tip `d65c628a2759d5e956d586c824172681553e187e6b0b194c86ff2f8a54dcccc9`, independently derived cumulative chainwork `0x10a50a3`, UTXO hash and count, and level-4 `verifychain(4,0)` covering 4,096 blocks and 4,121 transactions. The exact chain state and full verification must pass again offline after a clean shutdown. The reports retain wire-observed pending responses, separate receiver RPC in-flight snapshots, sampled resident size, owned-node CPU and task-attributed Darwin disk I/O counters.

## Fixed protocol and interpretation

Each CLI/GUI and delay combination has one A/B warmup pair and eight scored A/B/B/A/A/B/B/A cases. Correctness is required in all 40 fresh profiles.

- At 100 ms, every scored 128-limit case must have more than 16 wire-observed pending bodies. An unexercised ceiling makes the screen inconclusive. The median must fall and at least three of four adjacent pairs must favor the higher limit in each interface.
- At 0 ms, the higher median may increase by at most the greater of 100 ms and 5% of the 16-limit median. At most one adjacent pair may worsen by more than the greater of 200 ms and 10% of its 16-limit endpoint.
- Failure and incomplete attempts remain in the result. A positive screen supports the isolated delivery policy comparison on the sampled fixture. Whole-Mainnet catch-up time is outside this diagnostic.

The workflow captures the per-case result and the owned processes' ordinary logs. It excludes datadirs, cookies, wallets and the downloaded programs from the evidence artifact. Helpers and fixture inputs are locked by `inputs.sha256`. The body helper is adapted from the En.8 diagnostic to add signature and runtime evidence, full post-window VerifyDB and clean shutdown checks without moving the body clock.
