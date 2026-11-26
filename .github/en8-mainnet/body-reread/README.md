# Native Mainnet body reread diagnostic

The overlay profiles the existing `ConnectTip` reread path on native Windows x86-64 MSVCRT and UCRT and Apple ARM64. Standard GitHub runners download the existing verified release artifacts from [run 45841070388](https://github.com/Sugarchain-CI/sugarchain-en/actions/runs/45841070388). The workflow checks exact package checksums, source `8cae65e954ee78a1b40879c968ef2049d170930e`, and tree `a9b417f9093256338b09e095c42f8cb114040a65` before execution. `src/node/blockstorage.cpp` and `src/validation.cpp` are identical between that source and `3af0ccfb44e3f32b65e9d6bbcc20309528a8ac3f`.

## Protocol

Each sample opens a fresh owned node, disables wallet and public networking, and primes its headers from the verified early Mainnet 4,096-body fixture outside the body measurement. Its test-only minimum chainwork is zero to admit this early segment. Native block proof and script checks remain active with `-assumevalid=0`. The sole ordinary outbound fixture peer has no permissions and the request ceiling is held at 128. All delivered bodies must appear in a request exactly once.

| Sample order | Schedule for each contiguous group of eight requested heights |
|---|---|
| 1, in order | Send the lowest seven, wait for request removal, then release the highest |
| 2, held gap | Send the highest seven, wait for request removal, then release the lowest |
| 3, held gap | Same fixed schedule with a fresh profile |
| 4, in order | Same fixed schedule with a fresh profile |

Each barrier observes that the first seven heights have left `getpeerinfo.inflight` and the final held height is still listed. `RemoveBlockRequest` occurs within `ProcessMessage(BLOCK)` before its synchronous `ProcessBlock` call. Since all eight incoming messages share one TCP stream, the message handler finishes the first seven before processing the released body. The test also checks the full node debug ingress trace against the expected exact hash and peer order. This avoids extra `getblock` calls that would read and cache fixture file data. Both schedules receive the same network message count and exercise the same style of barrier without an injected response latency.

All samples must reach the pinned height-4,096 tip and the exact UTXO hash and count before and after a clean offline restart. The body profile uses a 110-second startup and delivery deadline. Barriers are bounded by that deadline and six seconds each. The offline restart has a 22-second verification deadline. The inherited helper bounds clean-stop attempts and fallback termination to the spawned test process. All four predeclared samples fit the 15-minute job budget under these limits.

## Measurements

- The primary results are `ConnectTip` reread counts and its reported disk-load time. The built-in cached-block marker identifies direct-memory connections. Reading the log from the post-priming offset prevents initialization records from entering the sample.
- The combined reread timing includes open and seek, reading, XOR handling, memory allocation, decode, and proof and indexed-hash checks. `ConnectBlock` elapsed time is reported separately. The application log rounds these timings to 0.01 ms. The reported phase times exclude time spent withholding the final fixture message.
- End-to-end sample wall time and node CPU include the controlled barriers and the RPC activity needed to observe them. The observer interval contains real validation alongside coordination, so the script does not subtract it to invent an adjusted throughput value. RSS is sampled before and after delivery. The paired results report the reread count and reread-load time differences across both fixed pairs.

The input contains 1,286,835 body bytes, a 308-byte median block, and 25 multi-transaction blocks. It is an early Mainnet diagnostic. Its disk load, decoding costs, and measured scheduling differences leave later-block conditions and whole Mainnet IBD duration unmeasured.

## Integration and validation

Copy only the two files under `overlay/.github/` onto the existing diagnostics checkout that contains `.github/en8-mainnet/delivery/` and the fixture. The workflow trigger is restricted to `ci/en8-native-body-reread`. It has no application builds, publication steps, or job-sized runner options. CI artifacts contain only `result.json`, wire-order records, and logs. Database directories remain runner-local.

Offline validation checked the real compressed and raw fixture hashes and geometry, the split request parser, the held-gap barrier, negative ingress-order detection, and the timing-counter parser. Workflow YAML and Bash syntax also passed. The native runtimes remain unexecuted.
