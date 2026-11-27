# En.8 native Regtest 100,000-block synchronization measurements

This benchmark downloads the published En.8 binaries without rebuilding them or running the general CI suite. It uses standard public GitHub-hosted runners; no Larger Runner, instruction-set emulator, or self-hosted runner is configured.

All cases use the same 100,000-block SHA256d Regtest fixture, exact terminal chainwork as `-minimumchainwork`, dbcache256, par1, parpow1, a common frozen clock and net debug logging. Each case runs three fresh receivers sequentially. An ordinary isolated loopback peer serves the exact data; no NoBan permission or direct receiver block import bypasses headers synchronization.

The timer starts immediately before receiver Popen and ends at the first RPC confirming height100000, the exact tip/chainwork, and initialblockdownload=false. Logs must prove PRESYNC start, transition to REDOWNLOAD at100000 and completed header redownload. Full level-4 chain verification, independent tip proof, UTXO digest and controlled shutdown are checked separately after the timed interval. Polling resolution is25ms. Sender fixture loading, package download and correctness checks are not included in the synchronization time.

Seven independent native jobs cover Linux x86-64, ARM64, native AArch32 compatibility where available, Windows UCRT/MSVCRT portable and extracted-installer daemon/GUI, and Apple Silicon/Intel macOS CLI/GUI. Interfaces on each runner run sequentially. PowerPC64 and RISC-V64 have no available native hosts and remain unmeasured. AArch32 GUI startup failures remain failures, never zero-second scores.

The fixture contains only coinbase transactions, and Regtest does not execute Mainnet Yespower or Mainnet-specific proof scheduling paths. Results compare this explicit workload on different recorded host hardware; they are not Mainnet IBD-duration forecasts.

Only compact receipts and compressed benchmark logs are uploaded with one-day artifact retention. Raw inputs, failed attempts and public asset hashes remain available for independent audit.
