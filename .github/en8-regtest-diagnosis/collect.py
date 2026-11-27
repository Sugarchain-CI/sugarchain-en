#!/usr/bin/env python3
"""Retain bounded compressed benchmark receipts/logs without binaries or chainstate."""
import argparse,hashlib,json,os,tarfile
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
files=[];skips={'package','packages','downloads','extracted','blocks','chainstate','wallets','indexes','xdg-data','xdg-config','xdg-cache','.git'}
if a.input.exists():
 for root,dirs,names in os.walk(a.input):
  dirs[:]=[d for d in dirs if d not in skips]
  for name in names:
   path=Path(root)/name
   if path.is_symlink() or not path.is_file():continue
   if path.suffix in ('.json','.log','.txt') and name not in ('.cookie',):files.append(path)
limit=2*1024**3;assert sum(p.stat().st_size for p in files)<limit
with tarfile.open(a.output/'evidence.tar.gz','w:gz',compresslevel=6) as t:
 for path in sorted(files):t.add(path,arcname=str(path.relative_to(a.input)),recursive=False)
receipt={'file_count':len(files),'uncompressed_bytes':sum(p.stat().st_size for p in files),'archive_bytes':(a.output/'evidence.tar.gz').stat().st_size,'sha256':hashlib.file_digest((a.output/'evidence.tar.gz').open('rb'),'sha256').hexdigest()}
(a.output/'collection.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
