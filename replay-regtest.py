from pathlib import Path
from time import monotonic
import json
import subprocess
import statistics
import sys

from profile_helper import Node, verify_reload, RECEIVER_TIME

executable, control, out = map(Path, sys.argv[1:])
source = control / "sender/regtest/blocks/blk00000.dat"
result = json.loads((control / "result.json").read_text())
out.mkdir()
samples = []
for i in range(3):
    work = out / f"receiver-{i}"
    work.mkdir()
    command = [str(executable), "-regtest", f"-datadir={work}", "-server=0",
               "-disablewallet=1", "-networkactive=0", "-listen=0", "-connect=0",
               "-dnsseed=0", "-discover=0", "-listenonion=0", "-checkblockindex=0",
               "-dbcache=256", "-par=1", "-parpow=1", "-blocksxor=0", "-printtoconsole=0",
               f"-mocktime={RECEIVER_TIME}", f"-loadblock={source}", "-stopatheight=10000"]
    started = monotonic()
    with (work / "profile-loader-console.log").open("wb") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120, check=True)
    elapsed = monotonic() - started
    with Node(executable, work, reopen=True) as checked:
        verify_reload(checked, result["blocks"], result["fixture_tip"], result["fixture_utxo_sha256"])
    samples.append(elapsed)
print(json.dumps({"samples": samples, "median": statistics.median(samples), "verified": True}))
