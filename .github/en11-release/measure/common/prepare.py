#!/usr/bin/env python3
import argparse,gzip,hashlib,json,shutil,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parent
info=json.loads((root/'fixture-info.json').read_text());compressed=root/'regtest-100000.dat.gz'
assert info['blocks']==info['frame_count']==100000 and info['network']=='regtest'
with compressed.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==info['compressed_sha256']
raw=a.output/'regtest-100000.dat'
with gzip.open(compressed,'rb') as f,raw.open('wb') as out:
 while chunk:=f.read(1024*1024):
  out.write(chunk);assert out.tell()<=info['raw_bytes']
with raw.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==info['fixture_sha256']
prev=info['genesis'];count=0
with raw.open('rb') as f:
 while header:=f.read(8):
  assert len(header)==8 and header[:4]==bytes.fromhex('fabfb5da')
  size=struct.unpack('<I',header[4:])[0];assert 80<size<4000000
  block=f.read(size);assert len(block)==size and block[4:36][::-1].hex()==prev
  prev=hashlib.sha256(hashlib.sha256(block[:80]).digest()).digest()[::-1].hex();count+=1
assert count==100000 and prev==info['tip']
shutil.copyfile(root/'fixture-info.json',a.output/'fixture-info.json')
print(json.dumps({'fixture':str(raw),'blocks':count,'tip':prev,'source':info['generator_source'],'emulation':False}))
