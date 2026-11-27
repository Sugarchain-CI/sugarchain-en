# En.8 macOS release packaging

The workflow checks out source commit `ba6ba77698f9a0759063604c4f87ce3eab93c107` and tree `585f08d47bc953b7863d2fc3ba51f3ea762bc36f` from the product repository. The workflow files and packaging helpers are separately checked out at the exact CI commit. The Darwin depends builds keep the shipping static Qt bundle and six CLI programs for each architecture. ARM64 keeps the En.7 Release `-O3` and IPO profile.

Each native standard macOS runner verifies its architecture, signs the distribution, reopens the actual ZIP and tar archives, and verifies the Mach-O signatures. The source's isolated data-directory contract, offline Mainnet wallet and Regtest GUI smoke, focused networking, cache, storage, and proof units, two crypto vector cases, and the one header proof functional test scope the release checks. The existing application identifier, app bundle root and archive filenames remain stable. These packages are ad-hoc signed and have no Apple notarization.

Each `en8-release-macos-{arch}` artifact contains four top-level files.

- `sugarchain-en-31.1.2-macos-{arch}-cli.tar.gz`
- `sugarchain-en-31.1.2-macos-{arch}.zip`
- `SHA256SUMS.release-inputs` with the two payload digests
- `macos-{arch}-provenance.json` with the exact source SHA and tree, workflow SHA and run ID, `assets` mapping payload basenames to SHA-256, native checks and validation-log digests

The release assembler copies the two payloads per architecture and verifies their hashes against both CI records. The `en8-macos-validation-{arch}` artifact retains logs separately. The transfer and validation artifacts are CI evidence. The final release checksum files are assembled and signed after all platforms are collected.
