# Windows Yespower scratch-page diagnostic

The isolated workflow compares CRT allocation, ordinary virtual pages, and a pageable 64 KiB allocation hint on one native AMD64 Windows runner with four logical CPUs. The probes use eight workers and the same 16,384 genuine Mainnet headers for every timed sample.

The base source is pinned to `81934405da9cdfeca55c2a07997b881c22993bc6`. The cross-compile job checks source file digests and records compiler, disassembly, and executable digests. The native job checks those executable digests before launch. The Mainnet header fixture comes from the first 16,384 entries of the continuous 100,000-header fixture with raw SHA-256 `f64a65677abdfa525b67d9a09291868fbfd1f9fb0d4089cdfafc3b2718dd07dd`.

Every native output must match the ordered 512-proof reference prefix from the independent Linux build. The full ordered outputs must also agree across all six samples. The private ABI experiment participates only in this correctness check. Production code and compiler settings are outside this overlay.

The two virtual allocation modes round to the same size and use pageable read/write memory. The hinted mode falls back to ordinary `VirtualAlloc` if the optional API is unavailable or returns failure. The forced-fallback control also checks ordered digests. A successful hint can still be backed by smaller physical pages. [Microsoft VirtualAlloc2 documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2)

The wall clock excludes scratch allocation and first-proof warm-up. The result records both separately along with allocation counts and accepted hints. This workload covers Yespower computation only.
