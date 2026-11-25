#!/usr/bin/env python3
"""Compare final ARM64 packages with the signed En.6 archives on one native runner."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

base,root,tools=map(Path,sys.argv[1:])
prefix='sugarchain-en-31.1.2-macos-arm64'
harness=tools/'native-sync.py'
records={'tests':{},'baseline':{},'old_sender':{},
         'harness_sha256':hashlib.sha256(harness.read_bytes()).hexdigest()}
old_daemon=root/'baseline'/f'{prefix}-cli/bin/sugarchaind'
new_daemon=base/'checked'/f'{prefix}-cli/bin/sugarchaind'
# The unchanged harness performs three fresh receivers and verified restarts per case.
# Alternate package order between networks; all compared cases run on this same host.
for network in ('regtest','testnet7'):
 for kind in ('cli','gui'):
  cohorts=('baseline','tests') if kind=='cli' else ('tests','baseline')
  for cohort in cohorts:
   candidate=cohort=='tests'
   folder=base/'checked' if candidate else root/'baseline'
   archive_folder=base/'release' if candidate else root/'baseline-archives'
   receiver=folder/(f'{prefix}-cli/bin/sugarchaind' if kind=='cli' else 'Sugarchain-Qt.app/Contents/MacOS/Sugarchain-Qt')
   archive=archive_folder/(f'{prefix}-cli.tar.gz' if kind=='cli' else f'{prefix}.zip')
   args=[sys.executable,str(harness),'--sender',str(new_daemon if candidate else old_daemon),
         '--receiver',str(receiver),'--platform','macos','--arch','arm64','--runner','macos-15',
         '--network',network,'--archive-sha256',hashlib.sha256(archive.read_bytes()).hexdigest()]
   if kind=='gui':args+=['--gui']
   if network=='testnet7':args+=['--fixture',str(tools/'testnet7-fixture.json')]
   work=root/f'{cohort}-{network}-{kind}'
   subprocess.run([*args,'--work-dir',str(work)],check=True)
   records[cohort][f'{network}-{kind}']=json.loads((work/'result.json').read_text())
   if candidate and network=='testnet7':
    args[args.index('--sender')+1]=str(old_daemon)
    work=root/f'old-sender-{network}-{kind}'
    subprocess.run([*args,'--work-dir',str(work)],check=True)
    records['old_sender'][f'{network}-{kind}']=json.loads((work/'result.json').read_text())
(base/'release/regtest-benchmark.json').write_text(json.dumps(records,indent=2)+'\n')
