# Windows block-index table-cache write guard

This standalone probe screens for regressions in synchronous index writes, status rewrites, and compaction as the LevelDB table cache changes. It links the bundled LevelDB and CRC32C code at Sugarchain source `9c502574b652804905d2533d51742ca91f694532` and checks the two vendor trees before building. The previous Windows 1,048,576-row storage probe used the same vendor trees.

| Arm | `max_open_files` | `small_table_cache` | Nominal table entries |
| --- | ---: | :---: | ---: |
| A | 1,000 | false | 990 |
| B | 10 | true | 0 |
| C | 42 | true | 32 |

LevelDB reserves ten file slots and divides its table LRU across 16 shards. Each arm uses the same 64 MiB database budget, 32 MiB block cache, 16 MiB write buffer, 32 MiB file-size target, 10-bit Bloom filter, checksum checks, and uncompressed SSTs. The native runner uses MSVC/UCRT and the bundled Windows environment implementation. Release-binary CRT/CPU behavior is covered by the separate product lifecycle runs.

The fixed sequence is A, B, C, C, B, A. Each trial creates a new database, inserts 1,048,576 unique deterministic `b` / `y` pairs, and synchronously writes up to 32,768 row IDs per batch. It forces compaction, rewrites all `b` values in the same synchronous batches, and compacts again. The `b` values model 90-byte header and 102-byte status/position records. The 33-byte `y` values remain unchanged and carry an invalid evidence version. After a normal close, a new cache opens the database and verifies the expected bytes and checksum of every record, both key counts, an ordered FNV-1a fingerprint, and ten point reads. All six fingerprints must match. The OS file cache follows the natural post-write state on reopen.

Report per-phase monotonic wall time and `GetProcessTimes` process CPU, per-batch latency, stalls, compaction stats, disk size, memory peaks, restart verification, and every mirrored C/A ratio. The write aggregate covers ingest, both compactions, status rewrites, and close. A wall or CPU ratio above 1.05 in both mirrors is a review signal. The result records all observations even when one pair disagrees. A small index-shaped database exercises write and compaction behavior. The previous same-scale fixture compacted into six to seven SSTs, so this fixture cannot qualify mature-index table residency or predict end-to-end synchronization.

Use `windows-write-guard-job.yml` as a job fragment, with `CMakeLists.txt`, `block-index-db-probe.cpp`, and `run_native.py` at `.github/en8-mainnet/cache-write-guard/`. The runner checks the exact checkout and selects the installed Visual Studio x64 generator. The probe also checks native AMD64 execution. Reserve 4 GiB free space. Builds have 60- and 180-second configure and build caps. Each trial has a 75-second cap. The job retains evidence on failure and excludes synthetic databases from upload.

For a local schema and restart smoke test, add `--smoke` to select 65,537 row IDs. This runs the same fixed sequence and exercises the partial final batch. Linux is available only in smoke mode. The Linux result is correctness evidence for the harness.
