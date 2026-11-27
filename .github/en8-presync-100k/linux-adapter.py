#!/usr/bin/env python3
"""Run released Linux binaries directly on native target hardware."""
import argparse,gzip,hashlib,json,os,platform,signal,struct,subprocess,tarfile,time,urllib.request
from pathlib import Path

def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--host',required=True);p.add_argument('--arch',required=True);p.add_argument('--pins',type=Path,required=True);p.add_argument('--harness',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--fixture-info',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 a.output.mkdir(parents=True,exist_ok=False)
 pins=json.loads(a.pins.read_text());assert pins['tag']=='v31.1.2-en.8' and pins['source']=='ba6ba77698f9a0759063604c4f87ce3eab93c107'
 actual=platform.machine().lower();assert platform.system()=='Linux'
 assert (a.arch=='x86_64' and actual=='x86_64') or (a.arch in ('arm64','armhf') and actual in ('aarch64','arm64'))
 name=f'sugarchain-en-31.1.2-{a.host}.tar.gz';pin=pins['assets'][name]
 downloads=a.output/'package';downloads.mkdir();archive=downloads/name
 req=urllib.request.Request(pin['url'],headers={'User-Agent':'Sugarchain-native-regtest-benchmark'})
 with urllib.request.urlopen(req,timeout=90) as response,archive.open('wb') as f:
  while block:=response.read(1024*1024):f.write(block)
 assert archive.stat().st_size==pin['bytes'] and sha(archive)==pin['sha256']
 with tarfile.open(archive) as t:t.extractall(downloads,filter='data')
 binpath=downloads/f'sugarchain-en-31.1.2-{a.host}'/'bin'
 executables={};expect={'x86_64':(2,62),'arm64':(2,183),'armhf':(1,40)}[a.arch]
 for name in ['sugarchaind','sugarchain-qt']:
  executable=binpath/name
  with executable.open('rb') as f:head=f.read(20)
  assert head[:4]==b'\x7fELF' and (head[4],struct.unpack('<H',head[18:20])[0])==expect
  executables[name]={'path':str(executable),'sha256':sha(executable),'elf_class':head[4],'elf_machine':expect[1]}
 results=[]
 for mode,name in [('daemon','sugarchaind'),('gui','sugarchain-qt')]:
  work=a.output/mode;log=a.output/f'{mode}-harness.log'
  cmd=['python3','-B',str(a.harness),'--sender',str(binpath/'sugarchaind'),'--receiver',str(binpath/name),'--fixture',str(a.fixture),'--fixture-info',str(a.fixture_info),'--work-dir',str(work),'--platform','linux','--arch',a.arch,'--archive-sha256',pin['sha256'],'--receiver-sha256',executables[name]['sha256'],'--trial-seconds','300']
  if mode=='gui':cmd+=['--gui']
  begin=time.perf_counter()
  try:
   with log.open('wb') as f:
    process=subprocess.Popen(cmd,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
    try:code=process.wait(timeout=1500)
    except subprocess.TimeoutExpired:
     os.killpg(process.pid,signal.SIGTERM)
     try:process.wait(timeout=8)
     except subprocess.TimeoutExpired:
      os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=8)
     raise
   status={'mode':mode,'returncode':code,'result':str(work/'result.json'),'elapsed_case_seconds':time.perf_counter()-begin}
  except Exception as e:status={'mode':mode,'error':f'{type(e).__name__}: {e}','elapsed_case_seconds':time.perf_counter()-begin}
  results.append(status)
  if 'error' in status:break
 name=f'sugarchain-en-31.1.2-{a.host}.tar.gz'
 summary={'source':pins['source'],'tag':pins['tag'],'host':a.host,'arch':a.arch,'native_host':platform.platform(),'native_machine':actual,'native_aarch32':a.arch=='armhf','emulation':False,'package':name,'archive_sha256':pin['sha256'],'executables':executables,'cases':results}
 (a.output/'platform-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(json.dumps({'host':a.host,'cases':results}))
 return 0 if all(x.get('returncode')==0 for x in results) else 1
if __name__=='__main__':raise SystemExit(main())
