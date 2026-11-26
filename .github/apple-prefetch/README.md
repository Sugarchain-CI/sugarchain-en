# Native Apple Silicon Yespower prefetch experiment

This isolated experiment uses source `81934405da9cdfeca55c2a07997b881c22993bc6`. In the native 100,000-header comparison, the candidate CLI averaged 179.20 seconds elapsed and 495.14 process CPU seconds. Saturating three virtual CPUs while doing the same CPU work gives an arithmetic floor of 165.05 seconds. That limits further savings from scheduling alone to 7.9% in the measured CLI stage. The GUI's corresponding floor is 137.20 seconds from 146.81 seconds measured, or 6.5%. These calculations apply to the measured PRESYNC workload. [Native comparison source](https://github.com/Sugarchain-CI/sugarchain-en/actions/runs/45799308927)

The signed candidate uses UMLAL in the PWX hot loop and EOR3 to combine XOR operations. The earlier paired-write experiment slowed the isolated proof loop. PWX updates have ordering dependencies because a later table read can consume an earlier write. The retained experiment addresses the separate, data-dependent 4 KiB input selected from `V`. Its pointer becomes available at the BlockMix call, and the function reads that input sequentially in 64-byte blocks. The existing explicit prefetch only compiles on x86. The Apple loop has no PRFM instruction.

The patch tests read hints at the start of the selected input and either 512 or 1,024 bytes ahead of the current pair. These distances correspond to four and eight reported 128-byte cache lines. Index checks bound pointer formation within the same input span. The experiment applies to the Apple ARM64 Yespower 1.0 pass. It preserves scratch allocation, reads, arithmetic, write order, proof results, verification rules, and all default build behavior. ARM hardware may choose how it handles prefetch hints. [Arm PRFM instruction](https://developer.arm.com/documentation/ddi0602/2026-03/Base-Instructions/PRFM--literal---Prefetch-memory--literal--?lang=en) · [Clang prefetch builtin](https://clang.llvm.org/docs/LanguageExtensions.html#builtin-prefetch)

## Run

Use the existing standard native macOS ARM64 runner with the pristine candidate checkout and the pinned gzip fixture containing Mainnet headers 1 through 100,000.

```bash
bash "$tools/run-native-prefetch.sh" "$candidate_source" "$headers_100k" "$RUNNER_TEMP/apple-prefetch"
```

Upload `$RUNNER_TEMP/apple-prefetch/evidence/` even if the job fails. Keep one job and one attempt for the planned comparison. Expected timed work is about two to three minutes across eight trials on the prior runner. Compilation and correctness checks add some time. Each timed trial has a 75-second timeout. A 20-minute job timeout allows failure artifacts to be retained.

The runner builds baseline and fixed-distance candidates with the same Apple Clang flags. Both use macOS 14.0 minimum deployment, the Apple M1 target, release optimization, and ThinLTO. It records the compiler target, verifies baseline EOR3 and candidate PRFM emission, runs differential vectors against the baseline, and compares complete 32-byte hashes for the first 8,192 actual Mainnet headers per timed trial. Each digest is also checked against its block's compact target. Each worker owns native scratch storage. There are eight workers, including the caller, and about 65 MiB of scratch across all contexts. Each candidate uses an independent baseline/candidate/candidate/baseline sequence on the same runner. Outputs and failures are retained.

Each candidate needs at least 8% lower process CPU time and elapsed time in both paired comparisons to justify a packaged-node test. If both qualify, choose the shorter distance for that test. A passing micro result remains a component measurement. Adoption would need native packaged CLI and GUI comparisons with the same stock Mainnet PRESYNC path and existing proof tests.

Local checks covered shell and C syntax, the pinned fixture chain through the measured prefix, and rejection of an out-of-target test digest. Native ARM64 verification and timing remain pending.
