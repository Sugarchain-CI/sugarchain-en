# Stock public Mainnet header timing

## Existing evidence

The six native En.7 75-second public-peer results under `/home/ak/.cache/codex-tmp/20261126T140933-883a202a25c2/{ci-results,windows-results}` retain aggregate state and two PRESYNC progress markers per case. The height progressed from 2,000 to 26,000. They have no request-level NET timestamps. The source-8ca native proof-credit output under `/home/ak/.cache/codex-tmp/20261126T160142-6036f6eca56e/presync-timeout-results` retains request and credit messages, but all six cases used an owned loopback fixture. The public window samples under `/home/ak/.cache/codex-tmp/20261126T204819-8360c070267b/witness-sample` measure body GETDATA. The inspected records do not establish public per-request header latency.

## Additive native probe

Place [public_header_wait.py](public_header_wait.py) under `.github/en8-mainnet/body-reread/` and apply [workflow-steps.yml](workflow-steps.yml) after the existing retained-package source, tree and checksum verification. The script reuses the `delivery/mainnet_probe.py` RPC helpers and runs the verified source-8ca CLI once each on Windows MSVCRT, Windows UCRT and native Apple Silicon. Its subprocess has a 72-second observation window and a 90-second process ceiling including cleanup. The temporary profile uses normal public seed discovery, default transport and minimum-chainwork, a disabled wallet, loopback-only RPC and disabled incoming P2P. It never connects to a nominated peer or grants permission flags. The artifacts exclude the datadir and RPC cookie.

The parser pairs completed established PRESYNC continuations from the same peer. It requires the nominal full header payload, local proof-time credit and matching normal follow-up log. The request-to-processing interval starts at `sending getheaders` and ends at `received: headers`. It is a queue-inclusive upper envelope, not a socket RTT or external-wire-only latency. Processing-to-follow-up time includes verification, local dispatch, commitment checks and logging. Credit records preserve the amount granted and its pre/post remaining budget. A grant with retained budget estimates verifier wall time in this bounded run. It is not process CPU time. Node observations with no completed established samples remain unmeasured. The step is independent of the body test and has no retry loop.

Stock `-capturemessages` records timestamps at application processing boundaries too. The probe uses ordinary NET logs and no capture, proxy, source build or request changes.

The parser was exercised offline against all six exact source-8ca native loopback logs. It recovered three completed rounds per log, rejected altered short responses and kept exhausted proof credit separate. No public probe or CI run was started during preparation.
