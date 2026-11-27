#!/usr/bin/env python3
"""Run normal debug-disabled binaries; keep profiled cases separate."""
import argparse,hashlib,json,os,platform,subprocess,sys,tarfile,urllib.request,zipfile,stat
from pathlib import Path,PurePosixPath
p=argparse.ArgumentParser();p.add_argument('--platform',required=True);p.add_argument('--arch',required=True);p.add_argument('--asset',required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--fixture-info',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--mode',choices=['baseline','profile'],required=True);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=True);root=Path(__file__).resolve().parent;pins=json.loads((root/'assets.json').read_text())
assert pins['source']=='ba6ba77698f9a0759063604c4f87ce3eab93c107'
labels=['ucrt','msvcrt'] if a.platform=='windows' else [a.arch]
packages={}
for label in labels:
 name=f'sugarchain-en-31.1.2-windows-x86_64-{label}-portable.zip' if a.platform=='windows' else a.asset
 pin=pins['assets'][name];dest=a.output/'packages'/label;dest.mkdir(parents=True,exist_ok=True);archive=dest/name
 if not archive.exists():
  req=urllib.request.Request(pin['url'],headers={'User-Agent':'Sugarchain-normal-native-diagnostic'})
  with urllib.request.urlopen(req,timeout=90) as response,archive.open('wb') as f:
   while chunk:=response.read(1024*1024):f.write(chunk)
 with archive.open('rb') as f:assert hashlib.file_digest(f,'sha256').hexdigest()==pin['sha256']
 assert archive.stat().st_size==pin['bytes']
 exe_name='sugarchaind.exe' if a.platform=='windows' else 'sugarchaind'
 exes=list(dest.rglob(exe_name))
 if not exes:
  if name.endswith('.zip'):
   with zipfile.ZipFile(archive) as z:
    for row in z.infolist():
     path=PurePosixPath(row.filename);assert not path.is_absolute() and '..' not in path.parts and not stat.S_ISLNK(row.external_attr>>16)
    z.extractall(dest)
  else:
   with tarfile.open(archive) as t:t.extractall(dest,filter='data')
  exes=list(dest.rglob(exe_name))
 assert len(exes)==1
 with exes[0].open('rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
 packages[label]={'asset':name,'archive_sha256':pin['sha256'],'binary_sha256':sha,'exe':str(exes[0].resolve())}
sequence=['ucrt','msvcrt','msvcrt','ucrt','ucrt','msvcrt'] if a.platform=='windows' and a.mode=='baseline' else labels
summary={'mode':a.mode,'source':pins['source'],'platform':a.platform,'architecture':a.arch,'host':{'platform':platform.platform(),'processor':platform.processor(),'logical_cpus':os.cpu_count(),'machine':platform.machine(),'runner':os.environ.get('RUNNER_NAME')},'packages':packages,'sequence':sequence,'runs':[]}
if sys.platform=='darwin':summary['host']['cpu']=subprocess.check_output(['/usr/sbin/sysctl','-n','machdep.cpu.brand_string'],text=True).strip()
if sys.platform.startswith('linux'):
 cpu=Path('/proc/cpuinfo').read_text();summary['host']['cpu_fields']=sorted({line for line in cpu.splitlines() if line.lower().startswith(('model name','hardware','cpu implementer','cpu architecture','cpu part'))})
file=a.output/f'{a.mode}-summary.json'
for i,label in enumerate(sequence,1):
 item=packages[label];work=a.output/f'{a.mode}-{i:02}-{label}';log=a.output/f'{a.mode}-{i:02}-{label}.log'
 cmd=[sys.executable,'-B',str(root/'regtest-normal.py'),'--common',str(root/'en8-regtest-presync.py'),'--resources',str(root/'resource_metrics.py'),'--sender',item['exe'],'--receiver',item['exe'],'--fixture',str(a.fixture),'--fixture-info',str(a.fixture_info),'--work-dir',str(work),'--platform',a.platform,'--arch',a.arch,'--archive-sha256',item['archive_sha256'],'--receiver-sha256',item['binary_sha256'],'--trials','1' if a.platform=='windows' or a.mode=='profile' else '3','--trial-seconds','300']
 if a.mode=='profile':cmd+=['--profiler',str(root/('windows_wpr_profile.py' if a.platform=='windows' else 'profile_macos.py'))]
 with log.open('wb') as f:result=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 summary['runs'].append({'label':label,'returncode':result.returncode,'work':work.name,'result':str(work/'result.json')});file.write_text(json.dumps(summary,indent=2)+'\n')
 print(a.mode,label,'exit',result.returncode,flush=True)
raise SystemExit(0 if all(x['returncode']==0 for x in summary['runs']) else 1)
