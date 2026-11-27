# En.8 Linux packaging

The five Linux targets keep the released tarball names, GUI and wallet. The PowerPC package targets big-endian PowerPC64. Each package contains static Qt with its existing XCB fallback, the pinned Fontconfig and FreeType shared libraries, and their dependency notices. Font selection uses the host's fonts.

Every target verifies installed ELF identity, required libraries and the archive digest. Native x86-64 and ARM64 runners also verify the extracted executables, Mainnet daemon startup, wallet address prefix and clean stop. Native x86-64 checks the Testnet7 GUI in X11 and XWayland session modes, exercises Fontconfig description metadata, and runs only the selected networking, proof, cache, block-manager, peer-manager, golden Yespower and SHA-256 checks. The narrow functional test uses the extracted release daemon. Cross-built ARM hard-float, big-endian PowerPC64 and RISC-V do not execute target binaries.

Each successful `en8-release-linux-<triplet>` artifact contains one `sugarchain-en-31.1.2-<triplet>.tar.gz` archive, `package.sha256`, product source and tree records, `provenance.json` and `checks/`. The product checkout is pinned independently from the workflow revision. The same-run provenance record binds the archive and each check log by SHA-256.
