#!/usr/bin/env python3
"""Require distinct runtime and specialized hot mixer paths before timing."""

import argparse
import hashlib
import json
from pathlib import Path
import re


LABEL = re.compile(r"^(_[\w.$]+):\s*$")
INSTRUCTION = re.compile(r"^([0-9a-f]+)\s+([\w.]+)\s*(.*?)\s*(?:;.*)?$")
REGISTER = r"[wx]\d+"
ARGUMENT_R_LOAD = re.compile(r"w\d+,\s*\[x3,\s*#(?:0x8|8)\]")
ARGUMENT_N_LOADS = (
    ("ldp", re.compile(r"w\d+,\s*w\d+,\s*\[x3\]")),
    ("ldr", re.compile(r"w\d+,\s*\[x3,\s*#(?:0x4|4)\]")),
)
CONSTANT_MASK = re.compile(r"[wx](\d+),\s*" + REGISTER + r",\s*#(?:0x7ff|2047)")
CONSTANT_INDEX = re.compile(REGISTER + r",\s*" + REGISTER + r",\s*#(?:0xc|12),\s*#(?:0xb|11)")
SCALED_INDEX = re.compile(r"x\d+,\s*x\d+,\s*[wx](\d+),\s*(?:lsl|uxtw)\s*#(?:0xc|12)")
ROW_SHIFT = re.compile(r"x(\d+),\s*x(\d+),\s*#(?:0xc|12)")
EXTENDED_ROW_SHIFT = re.compile(r"x\d+,\s*x\d+,\s*#(?:0xc|12),\s*#(?:0x20|32)")
GENERIC_ROWS = ("_blockmix_xor_save_1_0", "_blockmix_xor_1_0", "_blockmix_1_0")


def parse(disassembly):
    functions = {}
    current = None
    for line in disassembly.splitlines():
        if label := LABEL.fullmatch(line):
            current = label[1]
            if current in functions:
                raise ValueError(f"Duplicate native function label {current}")
            functions[current] = []
        elif current and (instruction := INSTRUCTION.fullmatch(line)):
            functions[current].append((int(instruction[1], 16), instruction[2], instruction[3]))
    return {name: body for name, body in functions.items() if body}


def branch_address(operands):
    try:
        return int(operands.rsplit(",", 1)[-1].strip(), 16)
    except ValueError:
        return None


def calls(functions):
    labels = {body[0][0]: name for name, body in functions.items()}
    graph = {}
    for name, body in functions.items():
        targets = set()
        for _, op, operands in body:
            if op in ("bl", "b"):
                target = operands if operands in functions else labels.get(branch_address(operands))
                if target is not None and target != name:
                    targets.add(target)
        graph[name] = targets
    return graph


def reachable(graph, entry):
    seen = set()
    pending = list(graph.get(entry, []))
    while pending:
        next_function = pending.pop()
        if next_function not in seen:
            seen.add(next_function)
            pending.extend(graph[next_function] - seen)
    return seen


def register_written(op, operands, register):
    return re.match(rf"[wx]{register}\b", operands) and not op.startswith(("st", "cmp", "tst", "b"))


def scaled_row_address(window, masked):
    for i, (address, op, operands) in enumerate(window):
        if op == "add" and (scale := SCALED_INDEX.fullmatch(operands)) and scale[1] == masked:
            return address
        if op == "lsl" and (shift := ROW_SHIFT.fullmatch(operands)) and shift[2] == masked:
            scaled = shift[1]
            uses_scaled = re.compile(rf"(?:x\d+,\s*x\d+,\s*x{scaled}\b|\[x\d+,\s*x{scaled}\])")
            for _, address_op, address_args in window[i + 1:]:
                if address_op.startswith(("add", "ld", "st")) and uses_scaled.search(address_args):
                    return address
                if register_written(address_op, address_args, scaled):
                    break
        if register_written(op, operands, masked):
            break
    return None


def row_witnesses(body, fixed_mask):
    by_address = {address: i for i, (address, _, _) in enumerate(body)}
    evidence = set()
    for tail, (address, op, operands) in enumerate(body):
        if not (op == "b" or op.startswith("b.") or op in ("cbz", "cbnz", "tbz", "tbnz")):
            continue
        target = branch_address(operands)
        head = by_address.get(target)
        if head is None or head >= tail:
            continue
        loop = body[head:tail]
        for i, (instruction_address, instruction, argument) in enumerate(loop):
            if not fixed_mask:
                if ((instruction == "lsl" and ROW_SHIFT.fullmatch(argument)) or
                        (instruction == "ubfiz" and EXTENDED_ROW_SHIFT.fullmatch(argument)) or
                        (instruction in ("add", "sub") and SCALED_INDEX.fullmatch(argument))):
                    evidence.add((target, address, instruction_address, "variable_row_index_constant_scale"))
                continue
            if instruction == "ubfiz" and CONSTANT_INDEX.fullmatch(argument):
                evidence.add((target, address, instruction_address, "merged_mask_scale"))
            if instruction == "and" and (mask := CONSTANT_MASK.fullmatch(argument)):
                scale = scaled_row_address(loop[i + 1:i + 9], mask[1])
                if scale is not None:
                    evidence.add((target, address, scale, "local_mask_and_address_scale"))
    return [{"loop": hex(head), "backedge": hex(tail), "instruction": hex(address), "shape": kind}
            for head, tail, address, kind in sorted(evidence)]


def inspect_mixer(functions, graph, name, fixed_reached, fixed_mask):
    body = functions.get(name, [])
    children = reachable(graph, name)
    witnesses = row_witnesses(body, fixed_mask)
    checks = {
        "entry_reaches_mixer": name in fixed_reached,
        "loop_has_constant_row_arithmetic": bool(witnesses),
        "mixer_has_pwx_products": any(op.startswith(("umlal", "umull")) for _, op, _ in body),
        "mixer_avoids_runtime_row_callees": not any(target.startswith(GENERIC_ROWS) for target in children),
    }
    return {"checks": checks, "row_index_witnesses": witnesses, "reachable_functions": sorted(children)}


def runtime_rows(functions, reachable_names, prefix, parameter):
    shift = re.compile(rf"x\d+,\s*x{parameter},\s*#(?:0x7|7)")
    return sorted(name for name in reachable_names if name.startswith(prefix) and
                  any(op == "lsl" and shift.fullmatch(operands) for _, op, operands in functions[name]))


def inspect(disassembly):
    functions = parse(disassembly)
    graph = calls(functions)
    generic_name = "_yespower"
    fixed_name = "_fixed_sugar_probe"
    generic = functions.get(generic_name, [])
    generic_reached = reachable(graph, generic_name)
    runtime_mix = {"smix1": runtime_rows(functions, generic_reached, "_blockmix_xor_1_0", 3),
                   "smix2": runtime_rows(functions, generic_reached, "_blockmix_xor_save_1_0", 2)}
    fixed_reached = reachable(graph, fixed_name)
    mixers = {name: inspect_mixer(functions, graph, name, fixed_reached, fixed_mask)
              for name, fixed_mask in (("_fixed_sugar_smix1", False), ("_fixed_sugar_smix2", True))}
    checks = {
        "generic_runtime_n": any(op == load and pattern.fullmatch(operands) for _, op, operands in generic
                                 for load, pattern in ARGUMENT_N_LOADS),
        "generic_runtime_r": any(op == "ldr" and ARGUMENT_R_LOAD.fullmatch(operands) for _, op, operands in generic),
        "generic_runtime_row_mixers": all(runtime_mix.values()),
        "both_fixed_main_mixers_verified": all(all(result["checks"].values()) for result in mixers.values()),
    }
    return {"status": "verified" if all(checks.values()) else "codegen_only", "checks": checks,
            "generic_dynamic_row_mixers": runtime_mix, "fixed_mixers": mixers,
            "fixed_reachable_functions": sorted(fixed_reached)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disassembly", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.disassembly.read_bytes()
    report = {**inspect(data.decode()), "disassembly_sha256": hashlib.sha256(data).hexdigest()}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(f"Native compiler evidence = {report['status']}")


if __name__ == "__main__":
    main()
