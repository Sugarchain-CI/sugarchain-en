"""Verify production compiler settings for the changed Windows code paths."""
import json,re,shlex,sys
from pathlib import Path
rows=json.loads(Path(sys.argv[1]).read_text())
required=('validation.cpp','yespower-opt.c','sha256.c','sha256.cpp')
result=[]
for name in required:
 matches=[row for row in rows if Path(row['file']).name==name and ('sha256' not in name or '/crypto/' in row['file'])]
 assert matches,name
 for row in matches:
  args=row.get('arguments') or shlex.split(row['command'])
  levels=[x for x in args if re.fullmatch(r'-O([0-9]|s|z|g|fast)?',x)]
  assert levels and levels[-1]=='-O3',(row['file'],levels)
  assert any(x.startswith('-flto') for x in args),row['file']
  if name in ('sha256.c','sha256.cpp'):
   assert any(x.startswith('-DENABLE_SSE41') for x in args),row['file']
   assert any(x.startswith('-DENABLE_X86_SHANI') for x in args),row['file']
  result.append({'file':row['file'],'optimization':levels[-1],'ipo':True})
Path(sys.argv[2]).write_text(json.dumps(result,indent=2)+'\n')
print('Verified Windows O3/IPO and matching SHA-NI dispatch compile definitions')
