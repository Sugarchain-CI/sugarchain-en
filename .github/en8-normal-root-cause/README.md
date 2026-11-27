# Normal-log native En.8 root-cause investigation

Use unchanged published En.8 daemons, the frozen100000-block Regtest chain, and `-debug=0` from before process launch. Standard Info logging remains; no body-stage logging toggle is performed. No product build, general CI suite, emulator, paid runner, operating user node or wallet is involved.

Three fresh baseline receivers per build retain the original Popen-to-exact-tip/chainwork/IBD=false timing window, owned-PID CPU/I/O counters, full level-4 validation, UTXO identity and controlled shutdown. Genuine PRESYNC is witnessed through one normal peer's positive intermediate `presynced_headers` while accepted headers remain0. Its final `headers` received-byte counter must be16.20–16.21MB (two passes of100000 serialized81-byte headers plus framing), with final same-peer accepted100000 and no presync. This replaces detailed net debug-log phase evidence without removing synchronization or validation.

Windows UCRT and MSVCRT run on ONE native runner in fixed U,M,M,U,U,M order, three fresh matched-CRT sender/receiver pairs each. This controls host identity; it does not separately isolate sender and receiver CRT costs. Linux x64/ARM64/nativeAArch32 and both Mac architectures use separate standard target runners whose actual CPU metadata is recorded. Cross-OS hardware differences remain explicit.

A separate unscored native profile case follows baseline measurement. Mac uses native sample on the two owned daemons, preserving named call graphs and a bounded body-phase capture. Windows uses a uniquely named WPR session plus a small pinned TraceEvent analysis helper; only the two daemon PIDs' CPU/module/RVA and file-operation aggregates are exported, never the all-host raw ETL. No trace is stopped or canceled unless this helper created its named session. Profile availability or qualification failure must not erase valid baseline records. Sampling can perturb the profile case, so its timing is never a baseline score.

Only the measurement helper (Windows ETW reader) is compiled; released product code is not rebuilt. Artifact retention is one day. Actual source, archive/fixture hashes, byte counters, resource units, profiler versions and failures are retained.

The user clarified the real40-hour report is Amana Windows10 running En.7. That computer is not among currently connected devices. The native En.8 Regtest diagnostic and En.7→En.8 source analysis are separate evidence; neither establishes a production Mainnet duration without the real run's configuration and phase logs.
