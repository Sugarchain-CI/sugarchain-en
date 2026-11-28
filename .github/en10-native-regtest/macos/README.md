# Published En.10 native macOS benchmark adapter

Run the shared 100,000-block Regtest benchmark against both published macOS interfaces on each native Apple Silicon and Intel runner. The release tag and its source are distinct from the source of a byte-identical carried runtime.

| Architecture | Native runner | CLI and GUI origin | Runtime commit |
|---|---|---|---|
| Apple Silicon | `macos-15` | En.8, carried through En.9 | `ba6ba77698f9a0759063604c4f87ce3eab93c107` |
| Intel | `macos-15-intel` | En.10 | `b68f5bf6844c52501f77a674d8cd8cfff2fabeb9` |

Each runner downloads only its CLI archive, GUI ZIP, and the En.10 checksum files. The checksum text is recovered from its cleartext OpenPGP signature and compared byte-for-byte, allowing a single omitted final line feed from the verifier. The four archive and embedded executable pins come from the verified published downloads and per-asset producer provenance. Both native payloads must be thin Mach-O, verify their ad hoc signatures and run on the declared architecture without Rosetta. [Signed En.10 release](https://github.com/decryp2kanon/sugarchain-en/releases/tag/v31.1.2-en.10)

The helper runs three fresh owned trials with the daemon and three with the actual Cocoa Qt application. Each uses the same included daemon as the fixture peer. The common harness is responsible for exact fixture identity, normal logging from creation, fresh profiles and ownership, positive PRESYNC evidence, both genuine header passes, active height 100,000 and `IBD=false`, and post-timing full level-4 verification, exact UTXO and clean exit. Preparation stays outside the receiver-start-to-completion clock. Worker, cache and file-XOR policies are those of the release. The common harness records the explicit synthetic isolation, clock/work-floor, assume-valid, debug and Regtest block-index diagnostic settings.

The adapter retains partial CLI evidence and runs the independent GUI mode if the CLI harness returns nonzero. Final artifacts contain adapter receipts and the common bounded log archive, with no runtime binaries or datadirs. This benchmark does not measure full Mainnet synchronization.
