# En.8 block-processing diagnostic

Run a bounded native diagnostic against unchanged published En.8 daemons and the same frozen Regtest100000 fixture. No build, general CI suite, paid runner, emulator or operating user node is involved.

Four fixed fresh cases run in ABBA order on each standard target runner. A retains `debug=net`. B disables only the net category on the receiver and sender after the receiver reports all100000 headers. All cases start with net logging, preserving actual PRESYNC and REDOWNLOAD evidence. A performs the corresponding logging RPCs with net remaining enabled. Record the exact switch height, time, resulting category flags and subsequent log volume. The additional RPCs distinguish these diagnostic cases from the earlier three-trial release comparison.

The timing boundary and full proof, chain, UTXO and controlled-shutdown requirements match the preceding test. Never omit failure cases or retry until a favorable performance value appears. Each case gets a fresh loaded sender and empty receiver. Only the body logging treatment differs; executable, fixture, proof threshold, cache, workers and frozen time are identical within a runner.

At receiver launch and the exact endpoint, sample only the explicitly owned sender/receiver PIDs. Preserve process-creation identity and cumulative CPU/I/O snapshots. Windows I/O counters count logical transfers and are not directly equivalent to the task-attributed disk bytes on Darwin/Linux. Raw counters, units, sample durations and endpoint sampling lag remain explicit. CPU counters may establish time spent executing or waiting, but do not identify individual kernel functions or physical-device latency.

Comparisons across different hosted CPUs cannot establish an operating-system-only effect. The within-run ABBA comparison tests body-network logging overhead. Mainnet-only caching, Yespower, real transaction loads, mature chainstate and the reported40-hour real Mainnet run are separate workloads.

Retain only bounded JSON and compressed logs for one day on GitHub; local evidence is preserved through the registered artifact store. All sources and release hashes are pinned in the shared inputs. Kernel counter modules fail explicitly on unsupported or inaccessible PIDs instead of substituting zero values.
