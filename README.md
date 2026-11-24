# Sugarchain En v31.1

Sugarchain En is a Sugarchain node and wallet based on Bitcoin Core v31.1. It
implements Sugarchain networking and consensus. The project homepage is
[sugarchain.org](https://sugarchain.org/).

For setup and platform build instructions, see the [documentation](doc/README.md).
Development takes place on the `en` branch of
[decryp2kanon/sugarchain-en](https://github.com/decryp2kanon/sugarchain-en).
See [CONTRIBUTING.md](CONTRIBUTING.md) to submit a focused pull request. Report
Sugarchain En issues, including GUI problems, in
[this repository](https://github.com/decryp2kanon/sugarchain-en/issues).

IBD performance benchmarks and reproduction guide: [IBD Optimization & Benchmarking](doc/ibd-optimization.md)

Historical Yespower auditing and reusable local results: [Lazy PoW Validation in the Background](doc/lazy-pow-validation.md)

## Regtest upgrade

Regtest now starts at 42.94967296 SUGAR per block and halves every 12,500,000
blocks. Start a fresh regtest data directory for this schedule. Blocks that
claimed the previous 50 SUGAR reward exceed the current subsidy limit.
Keep old regtest data separately if you need it for testing. The debug-only
`-regtest -test=bitcoinregtest` option selects the previous schedule for
precomputed test fixtures and old test-chain data.

New regtest receive addresses use `R…` for P2PKH, `r…` for P2SH, and
`rugar1…` for SegWit. Regtest still reads the previous En address formats
and opens wallets with those addresses, including imported watch-only
descriptors.
