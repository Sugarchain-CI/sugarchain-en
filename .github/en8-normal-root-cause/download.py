#!/usr/bin/env python3
import argparse,hashlib,json,urllib.request
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('names',nargs='+');a=p.parse_args();root=Path(__file__).resolve().parent;pins=json.loads((root/'assets.json').read_text());a.output.mkdir(parents=True,exist_ok=True)
for name in a.names:
 assert name==Path(name).name
 if name=='SHA256SUMS':pin={'sha256':pins['sha256sums_sha256'],'url':f"https://github.com/{pins['repository']}/releases/download/{pins['tag']}/SHA256SUMS"}
 else:pin=pins['assets'][name]
 out=a.output/name
 req=urllib.request.Request(pin['url'],headers={'User-Agent':'Sugarchain-native-regtest-benchmark'})
 with urllib.request.urlopen(req,timeout=90) as response,out.open('wb') as f:
  while chunk:=response.read(1024*1024):f.write(chunk)
 with out.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==pin['sha256']
 if 'bytes' in pin:assert out.stat().st_size==pin['bytes']
 print(name,'verified')
