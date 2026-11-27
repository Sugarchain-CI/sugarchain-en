# En.9 macOS release packaging

The workflow checks out source commit `ef4f3c07244505b8b1eb78d43f91dd5fa561b2bf` and tree `527d14fa0a9238828200ab643b56e718f3ba3bfb` from the product repository. The workflow files and packaging helpers are separately checked out at the exact CI commit. The Darwin depends builds keep the shipping static Qt bundle and six CLI programs for each architecture. ARM64 keeps the En.7 Release `-O3` and IPO profile.

The Intel Release candidate restores the En.6 C/C++ `-O3` and IPO profile with the default LLD LTO link level. After a successful cross-build, the Intel-only verifier reads the generated validation compile command and daemon and GUI link commands from the host-mounted CMake build directory. Each command must have effective `-O3` and `-flto=thin`, the existing Darwin x86-64 target and macOS 14.0 minimum. The log records three command digests. The compilation database and generated command files remain in the build directory.

Each native standard macOS runner verifies its architecture, signs the distribution, reopens the actual ZIP and tar archives, and verifies the Mach-O signatures. The source's isolated data-directory contract, offline Mainnet wallet and Regtest GUI smoke, focused networking, cache, storage, and proof units, two crypto vector cases, and the one header proof functional test scope the release checks. The existing application identifier, app bundle root and archive filenames remain stable. These packages are ad-hoc signed and have no Apple notarization.

Each `en9-release-macos-{arch}` artifact contains four top-level files.

- `sugarchain-en-31.1.2-macos-{arch}-cli.tar.gz`
- `sugarchain-en-31.1.2-macos-{arch}.zip`
- `SHA256SUMS.release-inputs` with the two payload digests
- `macos-{arch}-provenance.json` with the exact source SHA and tree, workflow SHA and run ID, `assets` mapping payload basenames to SHA-256, native checks and validation-log digests

The release assembler copies the two payloads per architecture and verifies their hashes against both CI records. The `en9-macos-validation-{arch}` artifact retains logs separately. The transfer and validation artifacts are CI evidence. The final release checksum files are assembled and signed after all platforms are collected.
