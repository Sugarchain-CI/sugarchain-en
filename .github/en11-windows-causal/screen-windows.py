#!/usr/bin/env python3
"""Measure separately scoped option effects in the same signed Windows daemon."""

import argparse
from contextlib import ExitStack
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
import math
import os
from pathlib import Path
import re
import statistics
import sys
import time
from unittest.mock import patch
import zipfile

COMMON_SHA = "01b1ebcebf9a651f005f7646c8ae30000d7e7aa11bb16ef503addc213f7693bb"
NORMAL_SHA = "02fa87aaccb2ba5556bd6e1b01ac67cdf2f785d2e161cf95e14df4637f56a3a4"
RESOURCE_SHA = "e4f2e41ec321303f0ddefcef9eac5f1277afc34ca70cfc5d573e55008b726814"
WINDOWS_RESOURCE_SHA = "8b1e4d457b36ef0893776f4624fafa4f3b20a08c58fff3f46834c1b250203d6d"
RELEASE_TOOLS_SHA = "bf5767544dc7c39dfbde6721a83b5c61625c04a355b00d4619ead56ee21e50de"
ARCHIVE = "sugarchain-en-31.1.2-windows-x86_64-ucrt-portable.zip"
ARCHIVE_SHA = "2e6338e0504a1a11589d0d8d6b3db6b92a3b8b2577dba3a1cdc4c6c0f24fa4b3"
PROGRAM_SHA = "0a7a056f4bdabc1648cc8e01e222696db8010df2f096de42ef36e6812fc428a1"
FOUR_FLAGS = {"blocksxor":"0","parpow":"1","par":"1","dbcache":"256"}
ARMS = {
    "stock": {"sender":{},"receiver":{}},
    "receiver-blocksxor0": {"sender":{},"receiver":{"blocksxor":"0"}},
    "receiver-parpow1": {"sender":{},"receiver":{"parpow":"1"}},
    "receiver-par1": {"sender":{},"receiver":{"par":"1"}},
    "receiver-dbcache256": {"sender":{},"receiver":{"dbcache":"256"}},
    "sender-blocksxor0": {"sender":{"blocksxor":"0"},"receiver":{}},
    "old-combined4-both": {"sender":FOUR_FLAGS,"receiver":FOUR_FLAGS},
}
ROLES = ("sender", "receiver")
NUMBER_FIELDS = ("cpu_user_seconds", "cpu_system_seconds", "read_bytes", "write_bytes")
PHASES = ("startup_through_headers", "observed_presync_to_full_headers", "post_headers_to_ibd_clear")


def need(condition, problem):
    if not condition:
        raise RuntimeError(problem)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_module(path, name, sha):
    need(path.is_file() and digest(path) == sha, f"Frozen module hash differs: {name}")
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def schedule():
    rows = []
    treatments = list(ARMS)[1:]
    for arm in ARMS:
        rows.append({"id": f"warm-{arm}", "phase": "warmup", "config": arm})
    rounds = (treatments, treatments[::-1], treatments[2:] + treatments[:2])
    for repeat, order in enumerate(rounds, 1):
        for arm in order:
            treatment_first = (repeat + treatments.index(arm)) % 2 == 0
            configs = (arm, "stock") if treatment_first else ("stock", arm)
            for ordinal, config in enumerate(configs, 1):
                rows.append({"id": f"pair-{repeat}-{arm}-{ordinal}-{config}", "phase": "scored",
                             "treatment": arm, "pair": repeat, "position": ordinal, "config": config})
    return rows


def release_input(tool, keyring, root, assets):
    root.mkdir()
    names = {name: tool.download(name, root, sha, assets) for name, sha in tool.SIGNED_FILES.items()}
    declarations = tool.verify_signature(names["SHA256SUMS"], names["SHA256SUMS.asc"], keyring, root)
    need(declarations.get(ARCHIVE) == ARCHIVE_SHA, "Signed UCRT portable archive pin differs")
    archive = tool.download(ARCHIVE, root, ARCHIVE_SHA, assets)
    need(archive.stat().st_size == 40_740_527, "Wrong public archive size")
    member = f"{archive.stem}/daemon/sugarchaind.exe"
    daemon = root / "sugarchaind.exe"
    with zipfile.ZipFile(archive) as package:
        rows = [entry for entry in package.infolist() if entry.filename == member]
        need(len(rows) == 1 and 0 < rows[0].file_size <= 128 * 1024**2,
             "Expected exactly one bounded daemon member in the published release")
        with package.open(rows[0]) as entry, daemon.open("xb") as target:
            while chunk := entry.read(1 << 20):
                target.write(chunk)
    need(tool.amd64_pe(daemon) == PROGRAM_SHA, "Exact native daemon PE32+ identity differs")
    return daemon, {
        "release": tool.TAG, "release_source": tool.SOURCE, "release_tree": tool.TREE,
        "runtime_source": tool.RUNTIME_SOURCE, "runtime_tree": tool.RUNTIME_TREE,
        "archive": ARCHIVE, "archive_sha256": ARCHIVE_SHA, "source_member": member,
        "daemon_sha256": PROGRAM_SHA, "signed_manifest_sha256": tool.SIGNED_FILES["SHA256SUMS"],
        "signer": tool.KEY,
    }


def treated_log(node, version, expected, receiver):
    # Keep the frozen common log requirements with an exact per-arm argv policy.
    flags = {}
    events = ({
        "ibd_latch":"Leaving InitialBlockDownload (latching to false)",
        "final_tip":f"UpdateTip: new best={node.fixture_tip} height=100000 ",
    } if receiver else {})
    marker = {key:[] for key in events}
    sources = []
    debug_count = 0
    raw = node.debug.read_text(encoding="utf-8", errors="replace")
    for number, line in enumerate(raw.splitlines(), 1):
        match = re.search(r"Sugarchain En version v31\.1\.2-([a-f0-9]{12}) ", line)
        if match:
            sources.append(match.group(1))
        option = re.search(r'Command-line arg: (dbcache|par|parpow|blocksxor)="([^"\r\n]*)"', line)
        if option:
            key, value = option.groups()
            need(key not in flags, f"Repeated measured option {key}")
            flags[key] = value
        if 'Command-line arg: debug="0"' in line:
            debug_count += 1
        for key, text in events.items():
            if text in line:
                marker[key].append({"line":number, "utc":line.split(" ", 1)[0]})
    need(debug_count == 1 and " [net] " not in raw, "Node did not keep debug logging disabled")
    need(sources == [version[:12]], "Runtime version differs from its pinned archive")
    need(flags == expected, f"Node treatment mismatch: expected {expected}, observed {flags}")
    need(all(len(items) == 1 for items in marker.values()), "Missing ordinary receiver IBD or active-tip marker")
    return {"disabled_from_start":True,"network_debug_lines":0,"runtime_source_prefix":sources[0],
            "benchmark_default_overrides":sorted(flags),"observed_explicit_options":flags,
            **{key:items[0] for key,items in marker.items()}}


class CaseHooks:
    def __init__(self, common, normal, resources, options):
        self.common = common
        self.normal = normal
        self.resources = resources
        self.options = options
        self.nodes = {}
        self.snapshots = {}
        self._node = normal.normal_node
        self._log = normal.info_log
        self._peer = normal.peer_observation
        self._tip = normal.await_tip

    def new_node(self, common, *args, **kwargs):
        node = self._node(common, *args, **kwargs)
        role = "sender" if kwargs.get("fixture") is not None else "receiver"
        need(role not in self.nodes, f"More than one {role} per fresh trial")
        self.nodes[role] = node
        reserved = {f"-{name}" for name in FOUR_FLAGS}
        need(not any(argument.partition("=")[0] in reserved for argument in node.argv),
             "Frozen common node already overrides release defaults")
        node.argv.extend(f"-{key}={value}" for key,value in self.options[role].items())
        return node

    def log(self, node, source, receiver=False):
        role = "receiver" if receiver else "sender"
        if self.options[role]:
            return treated_log(node, source, self.options[role], receiver)
        result = self._log(node, source, receiver=receiver)
        return {**result, "observed_explicit_options":{}}

    def capture(self, key):
        started = time.perf_counter()
        self.snapshots[key] = {
            **{role:self.normal.sample(self.resources, self.nodes[role]) for role in ROLES},
            "sample_start_seconds_since_launch": started-self.nodes["receiver"].started,
            "capture_seconds": time.perf_counter()-started,
        }

    def peer(self, receiver, sender, cap):
        state = self._peer(receiver, sender, cap)
        if (state and 0 < state["presynced_headers"] < self.common.HEIGHT
                and state["transport"] in ("v1","v2") and "observed_presync" not in self.snapshots):
            self.capture("observed_presync")
        return state

    def tip(self, common, receiver, sender, info, deadline, observation, on_full_headers):
        def full_headers():
            self.capture("full_headers")
            on_full_headers()
        return self._tip(common, receiver, sender, info, deadline, observation, full_headers)

    def measure(self, binary, fixture, info, directory, source):
        with ExitStack() as patches:
            for name, method in (("normal_node",self.new_node), ("info_log",self.log),
                                 ("peer_observation",self.peer), ("await_tip",self.tip)):
                patches.enter_context(patch.object(self.normal, name, method))
            outcome = self.normal.run_case(self.common, self.resources, None, binary, binary, fixture,
                                           info, directory, None, 300, source)
        return outcome

    def phases(self, outcome):
        timing = outcome["timing"]
        end = timing["endpoint"]["startup_to_ibd_clear_seconds"]
        full = timing["first_full_headers"]["seconds_since_launch"]
        early = timing["presync"]["seconds_since_launch"]
        need(0 < early < full < end <= 300, "Mismatch in the archived Regtest phase order")
        need(set(self.snapshots) == {"observed_presync","full_headers"}, "Required phase observations are missing")
        for stamp, observation in (("observed_presync",early),("full_headers",full)):
            capture = self.snapshots[stamp]
            gap = capture["sample_start_seconds_since_launch"] - observation
            need(math.isfinite(gap) and gap >= 0 and math.isfinite(capture["capture_seconds"])
                 and capture["capture_seconds"] >= 0, "Invalid phase resource timing")
        counters = outcome["process_resources"]
        epochs = {
            role: (
                counters[f"{role}_immediately_after_launch" if role=="receiver" else "sender_before_receiver_launch"],
                self.snapshots["observed_presync"][role], self.snapshots["full_headers"][role],
                counters[f"{role}_at_rpc_endpoint"],
            ) for role in ROLES
        }
        return {
            "startup_to_ibd_clear_seconds":end,
            "clock":"First clock before receiver Popen; resource deltas begin at the first owned-PID sample",
            "snapshots":self.snapshots,
            "windows":{
                label:{"wall_seconds":span,
                       **{role:self.normal.delta(epochs[role][begin],epochs[role][finish]) for role in ROLES}}
                for label,span,begin,finish in (
                    (PHASES[0],full,0,2), (PHASES[1],full-early,1,2), (PHASES[2],end-full,2,3)
                )
            }
        }


def compare(rows):
    fixed=schedule()
    need(len(rows)==len(fixed), "Missing frozen case slots")
    for received, expected in zip(rows,fixed,strict=True):
        need(all(received.get(key)==value for key,value in expected.items()), "Frozen case order differs")
    if any(row["status"]!="passed" for row in rows):
        return {"status":"incomplete","treatments":[]}
    result=[]
    for treatment in list(ARMS)[1:]:
        cases=[]
        for number in (1,2,3):
            pair=[row for row in rows if row.get("treatment")==treatment and row.get("pair")==number]
            need(len(pair)==2 and {row["config"] for row in pair}=={"stock",treatment}, "Pair identity mismatch")
            stock, option = sorted(pair,key=lambda row:row["config"]!="stock")
            a,b=(row["comparison"]["startup_to_ibd_clear_seconds"] for row in (stock,option))
            cases.append({"pair":number,"order":[row["config"] for row in pair],"stock_seconds":a,
                          "treatment_seconds":b,"treatment_minus_stock_seconds":b-a,
                          "treatment_minus_stock_percent":100*(b/a-1),
                          "phase_changes":{
                              key:{"wall_seconds":option["comparison"]["windows"][key]["wall_seconds"]
                                                 - stock["comparison"]["windows"][key]["wall_seconds"],
                                   **{role:{field: option["comparison"]["windows"][key][role][field] -
                                                    stock["comparison"]["windows"][key][role][field]
                                            for field in NUMBER_FIELDS} for role in ROLES}}
                              for key in PHASES
                          }})
        stock_median = statistics.median(row["stock_seconds"] for row in cases)
        treated_median = statistics.median(row["treatment_seconds"] for row in cases)
        paired_delta = statistics.median(row["treatment_minus_stock_seconds"] for row in cases)
        material = max(.25,.05*stock_median)
        wins = sum(row["treatment_minus_stock_seconds"]<0 for row in cases)
        result.append({"treatment":treatment,"pairs":cases,"faster_pairs":wins,
                       "stock_seconds_median":stock_median,"treatment_seconds_median":treated_median,
                       "median_paired_change_seconds":paired_delta,"material_seconds":material,
                       "material_improvement":wins==3 and paired_delta<=-material,
                       "interpretation":"material repeated improvement" if wins==3 and paired_delta<=-material
                                        else "inconclusive for material improvement",
                       "median_paired_change_percent":statistics.median(row["treatment_minus_stock_percent"] for row in cases)})
    return {"status":"complete","treatments":result}


def run(options):
    output=options.output
    output.mkdir(mode=0o700)
    result=output/"screen-result.json"
    rows=[{**row,"status":"not_started"} for row in schedule()]
    report={"schema":1,"status":"incomplete","kind":"native same-host UCRT Regtest option scope screen",
            "configurations":ARMS,"cases":rows,"profiling":False}
    save_path=lambda: save(result,report)
    save_path()
    try:
        need(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted",
             "Use one standard GitHub-hosted Windows runner")
        tool=read_module(options.release_tools,"causal_release_tools",RELEASE_TOOLS_SHA)
        report["host"]=tool.native_host()
        normal=read_module(options.common_dir/"regtest-normal.py","causal_normal",NORMAL_SHA)
        common=read_module(options.common_dir/"en8-regtest-presync.py","causal_common",COMMON_SHA)
        # resource_metrics imports its platform-specific implementation by name.
        need(digest(options.common_dir/"resource_windows.py")==WINDOWS_RESOURCE_SHA,"Wrong Windows counters")
        sys.path.insert(0,str(options.common_dir))
        resources=read_module(options.common_dir/"resource_metrics.py","causal_resources",RESOURCE_SHA)
        options.fixture.resolve(strict=True)
        info=common.fixture_metadata(options.fixture_info,options.fixture)
        report["fixture"]=info
        report["common_inputs"]={"normal":NORMAL_SHA,"base":COMMON_SHA,"resources":RESOURCE_SHA,
                                 "windows_resources":WINDOWS_RESOURCE_SHA}
        binary, report["package"]=release_input(tool,options.keyring,options.runtime,options.assets)
        common.native_environment("windows","x86_64")
        common.verify_binary(binary,"windows","x86_64")
        for row in rows:
            row["status"]="running"
            save_path()
            folder=output/row["id"]
            hooks=CaseHooks(common,normal,resources,ARMS[row["config"]])
            outcome=hooks.measure(binary,options.fixture,info,folder,tool.RUNTIME_SOURCE)
            if outcome["status"]=="passed":
                try:
                    row["comparison"]=hooks.phases(outcome)
                except (RuntimeError,OSError,TypeError,ValueError,KeyError) as error:
                    row.update(status="failed",error=f"{type(error).__name__}: {error}")
                else:
                    row["status"]="passed"
            else:
                row.update(status="failed",error=outcome.get("error","Frozen common correctness gate failed"))
            row["result_sha256"]=digest(folder/"result.json")
            save_path()
            print(f"{row['id']}: {row['status']}",flush=True)
            if not all(record.get("pid") is None or record.get("reaped") is True
                       for record in outcome["cleanup"].values()):
                break
        report["summary"]=compare(rows)
        report["status"]=report["summary"]["status"]
    except Exception as error:
        report["error"]=f"{type(error).__name__}: {error}"
        raise
    finally:
        save_path()
    return 0 if report["status"]=="complete" else 1


def save(path, data):
    pending=path.with_suffix(".tmp")
    pending.write_text(json.dumps(data,indent=2,allow_nan=False)+"\n",encoding="utf-8")
    pending.replace(path)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("common-dir","release-tools","keyring","fixture","fixture-info","runtime","output"):
        parser.add_argument(f"--{key}",required=True,type=Path)
    parser.add_argument("--assets",type=Path,help="Use pinned locally cached archives")
    args=parser.parse_args()
    for key,value in vars(args).items():
        if isinstance(value,Path):
            setattr(args,key,value.resolve())
    return run(args)


if __name__=="__main__":
    raise SystemExit(main())
