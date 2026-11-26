"""Compare verified En.7 artifacts and source-pinned candidate on a native host."""
import hashlib,json,os,platform,shutil,subprocess,sys,tarfile,zipfile
from pathlib import Path
from urllib.request import urlopen
here=Path(__file__).resolve().parent
root=Path(os.environ['RUNNER_TEMP'])/'en8-mainnet-paired'
root.mkdir(exist_ok=True)
manifest=json.loads((here/'baseline-hashes.json').read_text())
prefix='sugarchain-en-31.1.2-'
if platform.system()=='Darwin':
    assert platform.machine()=='arm64'
    specs=[('cli',prefix+'macos-arm64-cli.tar.gz','bin/sugarchaind',Path('staged')/(prefix+'macos-arm64-cli')/'bin/sugarchaind'),('gui',prefix+'macos-arm64.zip','Sugarchain-Qt.app/Contents/MacOS/Sugarchain-Qt',Path('staged/Sugarchain-Qt.app/Contents/MacOS/Sugarchain-Qt'))]
else:
    assert platform.system()=='Windows' and platform.machine().lower() in ('amd64','x86_64')
    crt=os.environ['CRT'];name=prefix+f'windows-x86_64-{crt}-portable.zip'
    specs=[('cli',name,'daemon/sugarchaind.exe',Path('bin/sugarchaind.exe')),('gui',name,'gui/sugarchain-qt.exe',Path('bin/sugarchain-qt.exe'))]
for mode,name,suffix,candidate in specs:
    destination=root/name
    if not destination.exists():
        with urlopen('https://github.com/decryp2kanon/sugarchain-en/releases/download/v31.1.2-en.7/'+name,timeout=90) as response,destination.open('wb') as output: shutil.copyfileobj(response,output)
    with destination.open('rb') as f: assert hashlib.file_digest(f,'sha256').hexdigest()==manifest[name],name
    extracted=root/(name+'.unpack')
    if not extracted.exists():
        extracted.mkdir()
        if name.endswith('.zip'):
            if platform.system()=='Darwin':subprocess.run(['ditto','-x','-k',str(destination),str(extracted)],check=True)
            else:
                with zipfile.ZipFile(destination) as z:z.extractall(extracted)
        else:
            with tarfile.open(destination) as t:t.extractall(extracted,filter='data')
    binaries=[p for p in extracted.rglob(Path(suffix).name) if p.as_posix().endswith(suffix)]
    assert len(binaries)==1,(name,binaries)
    if platform.system()=='Darwin':
        subprocess.run(['codesign','--verify','--strict',str(binaries[0])],check=True)
        assert subprocess.check_output(['lipo','-archs',str(candidate)],text=True).strip()=='arm64'
    command=[sys.executable,'-B',str(here/'mainnet_paired.py'),'--baseline',str(binaries[0].resolve()),'--candidate',str(candidate.resolve()),'--fixture',str(here/'mainnet-blocks.dat.gz'),'--fixture-info',str(here/'fixture.json'),'--output',str(root/mode),'--repeats','3']
    if mode=='gui':command+=['--gui']
    subprocess.run(command,check=True)
