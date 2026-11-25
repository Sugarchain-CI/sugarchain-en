# Sugarchain Testnet5

Start the daemon or the Qt wallet with `-testnet` or `-chain=test`. Pass the same option to the CLI. Use the `[test]` section in `sugarchain.conf` for test-network settings.

This mode uses the historical Sugarchain Testnet5 genesis, Yespower proof of work, and SugarShield difficulty adjustment. The default P2P port is `44230` and the default RPC port is `44229`. Chain data and wallets use the `testnet5` subdirectory. Bech32 receive addresses start with `tugar1q`.

Connect to a verified Testnet5 peer with `-addnode=<host>:44230`. The Testnet5 configuration currently has no built-in peer seeds. A new node may wait for a peer until an address is provided. Check chain and connection status with `sugarchain-cli -testnet getblockchaininfo` and `sugarchain-cli -testnet getpeerinfo`.

The focused functional test uses two loopback nodes with temporary data directories. It checks the historical chain identity, initial subsidy, native addresses, and a mined wallet transfer. The test overrides the historical minimum-work floor to exercise initial synchronization on a short local chain. Regular Testnet5 startup uses the historical floor.
