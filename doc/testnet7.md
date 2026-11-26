# Sugarchain Testnet7

Start the CLI or Qt node with `-testnet` or `-chain=test`. The configuration section is `[test]`, and `getblockchaininfo` reports `"chain": "test"`.

| Parameter | Value |
| --- | --- |
| Genesis block hash | `14f06e88eec9b21214a1eb54eee3cc03ceaf78ead1b16e40d8a383a5ff3e5e24` |
| Genesis time (UTC) | 2026-11-25 03:00:00 |
| Genesis coinbase text | `Sugarchain En Testnet7 2026-11-25` |
| Genesis bits and nonce | `1f3fffff`, `1320` |
| Genesis Yespower hash | `001c572d18bd3bda32894e8a13f3a0440a46d4eb62a24d31dd91bdd2f77545a4` |
| Data and wallet subdirectory | `testnet7` |
| P2P message start bytes | `c7 ee 5a 71` |
| Default P2P and RPC ports | `47230`, `47229` |
| Bech32 receive address prefix | `tugar1q` |
| First mined block subsidy | 42.94967296 SUGAR |

Testnet7 starts from a fresh chain. Its ledger, peers, and data directory are separate from Testnet5. Existing Testnet5 balances do not carry over.

Testnet7 uses Yespower and SugarShield with a five-second target block interval. There are currently no built-in peer seeds. To connect to a known Testnet7 peer, use `-addnode=<host>:47230`.

The functional test starts two isolated nodes with the default chain-work policy. It verifies the genesis identity, address handling, subsidy, mining, relay, a confirmed wallet transfer, and wallet restoration after restart.
