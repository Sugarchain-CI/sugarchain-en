#!/usr/bin/env python3
"""Keep worldwide release benchmark receipts and compressed owned-node logs."""

import argparse
import gzip
import json
from pathlib import Path
import shutil


def retain(source, destination):
    if not source.is_file():
        return False
    if source.is_symlink():
        raise ValueError(f"Unexpected linked evidence: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.suffix == ".gz":
        with source.open("rb") as incoming, gzip.open(destination, "xb", compresslevel=3) as output:
            shutil.copyfileobj(incoming, output, 1 << 20)
    else:
        with source.open("rb") as incoming, destination.open("xb") as output:
            shutil.copyfileobj(incoming, output, 1 << 20)
    return True


def collect(root, evidence, driver_log):
    evidence.mkdir()
    retained = []

    def copy(path, *, compress=False):
        relative = path + ".gz" if compress else path
        if retain(root / path, evidence / relative):
            retained.append(relative)

    for path in ("package-identity.json", "adapter-result.json", "release/release-signature-status.log"):
        copy(path, compress=path.endswith(".log"))
    for kind in ("portable", "installer"):
        for mode in ("daemon", "gui"):
            case = f"measurements/{kind}-{mode}"
            copy(f"{case}.adapter.json")
            copy(f"{case}.log", compress=True)
            copy(f"{case}/result.json")
            for profile in ("sender", "trial-01", "trial-02", "trial-03"):
                copy(f"{case}/{profile}/result.json")
                for log in ("debug.log", "console.log"):
                    copy(f"{case}/{profile}/{log}", compress=True)
    if driver_log and retain(driver_log, evidence / "adapter-console.log.gz"):
        retained.append("adapter-console.log.gz")
    with (evidence / "retained.json").open("x", encoding="utf-8") as output:
        json.dump({"retained": sorted(retained)}, output, indent=2)
        output.write("\n")
    print(f"Retained {len(retained)} receipt and log files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--driver-log", type=Path)
    args = parser.parse_args()
    collect(args.output, args.evidence, args.driver_log)
