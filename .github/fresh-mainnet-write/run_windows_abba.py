#!/usr/bin/env python3
"""Run one fixed native Windows UCRT fresh Mainnet comparison."""

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import time
from types import SimpleNamespace

import fresh_flatfiles
import index_evidence
import portable_fresh_mainnet_write as replay
import prepare_fresh_overlay as overlay
from process_resources import Resources

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "en8-mainnet" / "mature-checkpoint"))
import checkpoint_fixture

BASELINE = {
    "run": "45926384208", "source": "1b3029359223d7cee5da852762c04f2aac700a88",
    "tree": "8c9e821fa61317b218d437f7f211b5b5336e3a44",
    "manifest": "4c4ef37ddd09019e693221eb20424d1d241761a511811d695aec49819b62d489",
    "daemon": "6ccb4c7ab8bee0528773cfffa76b68b05d69bfb0fa86a46f6b13a7a278a1deb7",
}
BOUNDED = {
    "run": "45929224054", "source": "60f067d121651b8267b8d02c46fb221af4fc3529",
    "tree": "df36ec99710f16ddcdae0c12623db2034d362d99",
    "manifest": "db8a29695de4f79bb2f967b664f6cda45d3f84fdad80053470138b020db64949",
    "daemon": "05821a46cb376d1a8e5c885fb4df55f0ed500fff7238313078b481f6c646dfde",
}
ORDER = ("default", "bounded32", "bounded32", "default")
ARTIFACT_FILES = {
    "bin/sugarchain.exe", "bin/sugarchain-qt.exe", "bin/sugarchaind.exe", "bin/sugarchain-cli.exe",
    "bin/sugarchain-wallet.exe", "bin/sugarchain-tx.exe", "bin/sugarchain-util.exe",
    "Sugarchain-En-31.1.2-win64-setup.exe", "windows-installer-path.txt",
    "release-source-sha.txt", "release-source-tree.txt",
}
TIMING_FIELDS = (
    "first_header_send_to_observed_tip_seconds", "first_getdata_to_tip_log_seconds", "node_cpu_to_observed_tip_seconds",
    "flush_and_utxo_rpc_seconds", "flush_and_utxo_rpc_cpu_seconds", "startup_seconds", "offline_reopen_seconds",
)
CASE_SECONDS = 16 * 60


def emit(path, contents):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(contents, stream, indent=2, sort_keys=True)
        stream.write("\n")


def verified_binary(package, pin):
    manifest = overlay.signed_input(package / "SHA256SUMS.release-inputs", pin["manifest"], 8192)
    counted = set()
    for line in manifest.decode("ascii").splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", line)
        overlay.require(match and match[2] in ARTIFACT_FILES and match[2] not in counted, "Unexpected native package member")
        path = package / match[2]
        overlay.require(path.resolve(strict=True) == path, "Package member path has an alias")
        info = path.lstat()
        overlay.regular(info, path)
        with overlay.open_source(path, overlay.signature(info)) as stream:
            overlay.require(hashlib.file_digest(stream, "sha256").hexdigest() == match[1], "Native package member SHA-256 mismatch")
        counted.add(match[2])
    overlay.require(counted == ARTIFACT_FILES and
                    (package / "release-source-sha.txt").read_text().strip() == pin["source"] and
                    (package / "release-source-tree.txt").read_text().strip() == pin["tree"],
                    "Native package source or tree identity mismatch")
    binary = package / "bin/sugarchaind.exe"
    replay.executable(binary, pin["daemon"])
    return binary


def get_fixture(public, delta):
    manifest_path = public / "manifest.json"
    package = checkpoint_fixture.load_manifest(manifest_path, overlay.BASE_SHA)
    base = overlay.json_no_duplicates(overlay.signed_input(manifest_path, overlay.BASE_SHA, overlay.MANIFEST_LIMIT))
    update = overlay.json_no_duplicates(overlay.signed_input(delta / "overlay-manifest.json", overlay.MANIFEST_SHA,
                                                           overlay.MANIFEST_LIMIT))
    before, after, members = overlay.manifests(base, update)
    archive = overlay.signed_input(delta / "fresh-tail-overlay.tar.gz", overlay.ARCHIVE_SHA,
                                   overlay.ARCHIVE_BYTES, overlay.ARCHIVE_BYTES)
    replacement_data = overlay.decode_overlay(archive, members)
    replay.load_tail(delta / "mature-mainnet-tail.dat")
    overlay.signed_input(delta / "anchor-header.bin", replay.ANCHOR_HEADER_SHA, 80, 80)
    overlay.signed_input(delta / "converter-cursors.json", replay.CURSORS_SHA, 4096)
    return package, before, after, replacement_data


def preflight(args):
    package, before, after, replacements = get_fixture(args.public_fixture, args.overlay_fixture)
    compressed = sum(row["bytes"] for row in package["archive_parts"])
    base = sum(row["bytes"] for row in before.values())
    new = sum(row["bytes"] for row in after.values())
    free = shutil.disk_usage(args.output.parent).free
    need = compressed + base + new + overlay.RESERVE
    emit(args.output, {"status": "ready" if free >= need else "disk_capacity_inconclusive",
                       "required_free_bytes": need, "observed_free_bytes": free, "public_archive_bytes": compressed,
                       "base_bytes": base, "new_target_bytes": new, "reserve_bytes": overlay.RESERVE,
                       "target_file_count": len(after), "replacement_count": len(replacements),
                       "base_manifest_sha256": overlay.BASE_SHA, "overlay_manifest_sha256": overlay.MANIFEST_SHA})
    overlay.require(free >= need, "Insufficient space for downloaded parts, exact base and new receiver")


def receipt(target, after):
    return {
        "schema": 1, "status": "fresh_overlay_verified", "datadir": str(target),
        "base_manifest_sha256": overlay.BASE_SHA, "overlay_manifest_sha256": overlay.MANIFEST_SHA,
        "archive_sha256": overlay.ARCHIVE_SHA, "anchor_height": overlay.ANCHOR_HEIGHT, "anchor_hash": overlay.ANCHOR,
        "target_tip_height": overlay.TIP_HEIGHT, "target_tip_hash": overlay.TIP,
        "full_file_count": len(after), "full_file_bytes": sum(row["bytes"] for row in after.values()),
        "replacement_file_count": 7, "obsolete_file_count": 5,
    }


def paired(first, second, third, fourth):
    ratios = {}
    for name in TIMING_FIELDS:
        overlay.require(first[name] > 0 and fourth[name] > 0 and second[name] >= 0 and third[name] >= 0,
                        "Invalid timing or zero reference interval")
        ratios[name] = [second[name] / first[name], third[name] / fourth[name]]
    for name in ("block_and_undo_ms", "block_index_ms"):
        # The native log rounds to 0.01 ms. Leave a zero reference ratio undefined.
        results = [row["forced_flush"][name] for row in (first, second, third, fourth)]
        overlay.require(all(value >= 0 for value in results), "Invalid force-sync timing")
        ratios[name] = [results[1] / results[0] if results[0] > 0 else None,
                        results[2] / results[3] if results[3] > 0 else None]
    return ratios


async def bounded_sample(args):
    async with asyncio.timeout(CASE_SECONDS):
        await replay.run(args)


def run(args):
    report_dir, work = args.output, args.scratch
    for path in (report_dir, work):
        overlay.require(path.is_absolute() and path.parent.resolve(strict=True) == path.parent and not path.exists(),
                        "Expected two new canonical job directories")
    overlay.require(report_dir != work and work not in report_dir.parents and report_dir not in work.parents,
                    "Report and disposable fixture directories must be separate")
    report_dir.mkdir()
    work.mkdir()
    sequence = {"schema": 1, "status": "incomplete", "order": list(ORDER), "arms": [], "per_case_seconds": CASE_SECONDS}
    try:
        sequence["host"] = Resources().host()
        host_ram = sequence["host"]["physical_bytes"]
        overlay.require(4 << 30 <= host_ram <= 16 << 30, "Runner is outside the exact default/cache policy scope")
        inputs = {
            "default": (verified_binary(args.baseline, BASELINE), BASELINE),
            "bounded32": (verified_binary(args.candidate, BOUNDED), BOUNDED),
        }
        sequence["native_artifacts"] = {"default": BASELINE, "bounded32": BOUNDED}
        extractor = args.index_exporter
        with extractor.open("rb") as source:
            sequence["exporter_sha256"] = hashlib.file_digest(source, "sha256").hexdigest()
        package, before, after, replacements = get_fixture(args.public_fixture, args.overlay_fixture)
        base = work / "base"
        need = sum(item["bytes"] for item in before.values()) + sum(item["bytes"] for item in after.values()) + overlay.RESERVE
        overlay.require(shutil.disk_usage(work).free >= need, "Insufficient disk for exact public base and new independent target")
        sequence["source_extraction"] = checkpoint_fixture.extract(args.public_fixture, package, base, time.monotonic() + 300)
        completed = []
        for number, name in enumerate(ORDER, 1):
            label = f"{number:02d}-{name}"
            case_dir = report_dir / label
            case_dir.mkdir()
            target = work / label
            arm = {"name": label, "variant": name, "status": "preparing"}
            sequence["arms"].append(arm)
            prep_start = time.monotonic()
            overlay.build(base, target, before, after, replacements)
            marker = case_dir / "fixture-receipt.json"
            emit(marker, receipt(target, after))
            arm["preparation_seconds"] = time.monotonic() - prep_start
            arm["status"] = "sample_running"
            executable, pin = inputs[name]
            bench = SimpleNamespace(
                binary=executable, binary_sha256=pin["daemon"], datadir=target,
                overlay_receipt=marker, overlay_manifest=args.overlay_fixture / "overlay-manifest.json",
                cursor_receipt=args.overlay_fixture / "converter-cursors.json",
                tail=args.overlay_fixture / "mature-mainnet-tail.dat", anchor_header=args.overlay_fixture / "anchor-header.bin",
                output=case_dir / "sample", startup_timeout=480, history_timeout=240, delivery_timeout=180, shutdown_timeout=90,
            )
            asyncio.run(bounded_sample(bench))
            result_path = bench.output / "result.json"
            result = json.loads(result_path.read_text())
            overlay.require(result["status"] == "fresh_write_verified_pending_disk_audit" and
                            result["binary_sha256"] == pin["daemon"] and result["source_commit"] == pin["source"] and
                            result["receiver_datadir"] == str(target), "Unexpected native replay result")
            arm["status"] = "flat_file_audit"
            audited, positions = fresh_flatfiles.verify(target, bench.tail, result["original_body_end"], result["original_undo_end"])
            emit(case_dir / "flat-file-audit.json", audited)
            packed = (json.dumps(positions, separators=(",", ":")) + "\n").encode("ascii")
            overlay.require(len(packed) <= 1 << 20, "Fresh storage position evidence exceeds byte cap")
            with (case_dir / "flat-file-positions.json").open("xb") as position_file:
                position_file.write(packed)
            arm["status"] = "raw_index_export"
            index = index_evidence.export(extractor, work, target, case_dir, bench.tail)
            index.update(case=label, result_sha256=overlay.sha(result_path.read_bytes()),
                         flat_file_positions_sha256=overlay.sha(packed), cache_policy=arm["variant"],
                         binary_sha256=pin["daemon"], source_commit=pin["source"],
                         exporter_sha256=sequence["exporter_sha256"])
            emit(case_dir / "index-export.json", index)
            arm["status"] = "passed"
            arm["result_sha256"] = overlay.sha(result_path.read_bytes())
            arm["metrics"] = {key: result[key] for key in TIMING_FIELDS}
            arm["flat_file_frame_pairs"] = audited["verified_frame_pairs"]
            completed.append(result)
            claim = target / ".fresh-mainnet-write-claimed"
            overlay.require(target.parent == work and target.resolve(strict=True) == target and
                            not (target / ".cookie").exists() and claim.read_text().strip() == str(bench.output),
                            "Refusing to remove a profile without the expected closed ownership claim")
            shutil.rmtree(target)
        sequence["ratios_bounded32_over_default_in_bracket_order"] = paired(*completed)
        sequence["status"] = "verified_native_four_case_fresh_write_comparison"
        sequence["stock_typed_index_audit"] = "awaiting_independent_decode"
    except BaseException as error:
        sequence["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        emit(report_dir / "sequence.json", sequence)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--preflight", action="store_true")
    for option in ("public-fixture", "overlay-fixture", "output"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    for option in ("baseline", "candidate", "index-exporter", "scratch"):
        parser.add_argument(f"--{option}", type=Path)
    args = parser.parse_args()
    if args.preflight:
        preflight(args)
        return
    if not all((args.baseline, args.candidate, args.index_exporter, args.scratch)):
        parser.error("Four-case comparison requires baseline, candidate, index exporter and scratch paths")
    for name in ("baseline", "candidate", "public_fixture", "overlay_fixture", "index_exporter"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    run(args)


if __name__ == "__main__":
    main()
