#!/usr/bin/env python3
"""Launch a diagnostic against one pinned, unchanged published daemon."""
import argparse,hashlib,json,platform,subprocess,sys,tarfile,urllib.request,zipfile,stat
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser();p.add_argument('--platform',choices=['linux','macos','windows'],required=True);p.add_argument('--arch',required=True);p.add_argument('--asset',required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--fixture-info',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False);root=Path(__file__).resolve().parent
pins=json.loads((root/'assets.json').read_text());assert pins['source']=='ba6ba77698f9a0759063604c4f87ce3eab93c107'
pin=pins['assets'][a.asset];package=a.output/'package';package.mkdir();archive=package/a.asset
request=urllib.request.Request(pin['url'],headers={'User-Agent':'Sugarchain-native-block-diagnostic'})
with urllib.request.urlopen(request,timeout=90) as response,archive.open('wb') as f:
 while chunk:=response.read(1024*1024):f.write(chunk)
with archive.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==pin['sha256']
assert archive.stat().st_size==pin['bytes']
if a.asset.endswith('.zip'):
 with zipfile.ZipFile(archive) as z:
  for row in z.infolist():
   path=PurePosixPath(row.filename);assert not path.is_absolute() and '..' not in path.parts and not stat.S_ISLNK(row.external_attr>>16)
  z.extractall(package)
else:
 with tarfile.open(archive) as t:t.extractall(package,filter='data')
name='sugarchaind.exe' if a.platform=='windows' else 'sugarchaind'
executables=list(package.rglob(name));assert len(executables)==1
exe=executables[0].resolve()
with exe.open('rb') as f:binary_hash=hashlib.file_digest(f,'sha256').hexdigest()
command=[sys.executable,'-B',str(root/'diag-presync.py'),'--common',str(root/'en8-regtest-presync.py'),'--resources',str(root/'resource_metrics.py'),'--sender',str(exe),'--receiver',str(exe),'--fixture',str(a.fixture),'--fixture-info',str(a.fixture_info),'--work-dir',str(a.output/'measurements'),'--platform',a.platform,'--arch',a.arch,'--archive-sha256',pin['sha256'],'--receiver-sha256',binary_hash,'--trial-seconds','300']
with (a.output/'launcher.log').open('wb') as log:
 result=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
(a.output/'launcher-result.json').write_text(json.dumps({'asset':a.asset,'source':pins['source'],'archive_sha256':pin['sha256'],'receiver_sha256':binary_hash,'returncode':result.returncode,'native_host':platform.platform()},indent=2)+'\n')
print(json.dumps({'asset':a.asset,'returncode':result.returncode,'result':str(a.output/'measurements/result.json')}))
raise SystemExit(result.returncode)
