#!/usr/bin/env python3
"""Qualify each Windows CRT on one native host with exact packaged binaries."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time

PINNED_COMMON = {
    "en8-regtest-presync.py": "01b1ebcebf9a651f005f7646c8ae30000d7e7aa11bb16ef503addc213f7693bb",
    "regtest-normal.py": "02fa87aaccb2ba5556bd6e1b01ac67cdf2f785d2e161cf95e14df4637f56a3a4",
    "resource_metrics.py": "e4f2e41ec321303f0ddefcef9eac5f1277afc34ca70cfc5d573e55008b726814",
    "resource_windows.py": "8b1e4d457b36ef0893776f4624fafa4f3b20a08c58fff3f46834c1b250203d6d",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()


def write(path, data):
    path.write_text(json.dumps(data,indent=2,allow_nan=False)+"\n",encoding="utf-8")


def collect(out, summary):
    index = out / "comparison-summary.json"
    write(index, summary)
    selected = {index}
    selected.update(out / name for name in ("prepare-inputs.log","cli-run.log","gui-run.log"))
    signature = out / "inputs/baseline-signature"
    selected.update(signature / name for name in ("release-signature-verification.json","release-signature-status.log"))
    for interface in ("cli","gui"):
        base = out / interface
        selected.add(base / "result.json")
        for case in base.glob("*"):
            if not case.is_dir() or not case.name.startswith(("warmup-","matched-","receiver-isolation-")):
                continue
            selected.update(case / name for name in ("worker-result.json","worker.log","node-evidence/result.json"))
            selected.update(case / f"node-evidence/{role}/{log}"
                            for role in ("sender","receiver") for log in ("debug.log","console.log"))
    files = sorted(path for path in selected if path.is_file() and not path.is_symlink())
    if sum(path.stat().st_size for path in files) > 256*1024**2:
        raise RuntimeError("Unexpectedly large evidence inventory")
    manifest = out / "evidence-files.json"
    write(manifest,[{"path":path.relative_to(out).as_posix(),"bytes":path.stat().st_size,"sha256":digest(path)}
                    for path in files])
    with tarfile.open(out / "evidence.tar.gz","w:gz") as archive:
        for path in [*files,manifest]:
            archive.add(path,arcname=path.relative_to(out).as_posix(),recursive=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform",choices=("windows",),required=True)
    parser.add_argument("--candidate-dir",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--crt",choices=("ucrt","msvcrt"),required=True)
    args=parser.parse_args()
    tools=Path(__file__).resolve().parent
    common=tools/"common"
    output=args.output.resolve()
    output.mkdir()
    source, tree=os.environ["PRODUCT_SOURCE"],os.environ["PRODUCT_TREE"]
    started=time.monotonic()
    summary={"source":source,"tree":tree,"platform":"windows","crt":args.crt,"cases":[],"status":"failed",
             "baseline_tag":"v31.1.2-en.10","fixed_sender":"baseline"}
    try:
        for name, expected in PINNED_COMMON.items():
            if digest(common/name)!=expected:
                raise RuntimeError(f"Changed frozen common helper {name}")
        subprocess.run([sys.executable,"-B",str(common/"prepare.py"),"--output",str(output/"fixture")],
                       check=True,timeout=90)
        command=[sys.executable,"-B",str(tools/"prepare-paired-inputs.py"),"--platform","windows",
                 "--candidate-dir",str(args.candidate_dir.resolve()),"--baseline-pins",str(tools/"assets.json"),
                 "--release-tools",str(tools/"release-tools.py"),"--keyring",str(tools/"release-public.gpg"),
                 "--candidate-source",source,"--candidate-tree",tree,"--output",str(output/"inputs"),
                 "--crt",args.crt]
        with (output/"prepare-inputs.log").open("wb") as log:
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=600)
        for interface in ("cli","gui"):
            result_path=output/interface/"result.json"
            command=[sys.executable,"-B",str(tools/"regtest-release-paired.py"),
                     "--manifest",str(output/"inputs"/f"{interface}.json"),
                     "--common",str(common/"en8-regtest-presync.py"),"--normal",str(common/"regtest-normal.py"),
                     "--resources",str(common/"resource_metrics.py"),
                     "--fixture",str(output/"fixture"/"regtest-100000.dat"),
                     "--fixture-info",str(output/"fixture"/"fixture-info.json"),
                     "--work-dir",str(result_path.parent),"--candidate-source",source,"--candidate-tree",tree,
                     "--trial-seconds","300","--total-seconds","2100"]
            with (output/f"{interface}-run.log").open("wb") as log:
                run=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,timeout=2200)
            receipt=json.loads(result_path.read_bytes()) if result_path.is_file() else {}
            summary["cases"].append({"interface":interface,"returncode":run.returncode,
                                     "case_count":len(receipt.get("cases",[])),
                                     "performance_passed":receipt.get("performance_gate",{}).get("passed",False)})
            print(interface,"exit",run.returncode,flush=True)
        passed=all(x["returncode"]==0 and x["case_count"]==14 and x["performance_passed"] for x in summary["cases"])
        summary["status"]="passed" if passed else "failed"
    except Exception as error:
        summary["error"]=f"{type(error).__name__}: {error}"
    finally:
        summary["elapsed_seconds"]=time.monotonic()-started
        collect(output,summary)
    return int(summary["status"]!="passed")


if __name__=="__main__":
    raise SystemExit(main())
