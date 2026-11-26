#!/usr/bin/env python3
"""Require the fused control and the independent native product/add sequences."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re


REFERENCE = ("blockmix_1_0", "blockmix_xor_1_0", "blockmix_xor_save_1_0")
EXPECTED = (12, 24, 24)
EOR3 = (1, 9, 9)
TAILS = ("blockmix_salsa_1_0", "blockmix_salsa_xor_1_0", "")
VECTOR = re.compile(r"\b[vqdshb](\d+)\b")
STACK = re.compile(r"\[(?:sp|x29)\b")


def product_pairs(body):
    pairs = []
    for i, (address, opcode, operands) in enumerate(body):
        if opcode != "umull.2d":
            continue
        product = operands.split(",", 1)[0].strip()
        for add_address, add_opcode, add_operands in body[i + 1:i + 25]:
            regs = [name.strip() for name in add_operands.split(",")]
            if add_opcode == "add.2d" and product in regs[1:]:
                pairs.append([hex(address), hex(add_address)])
                break
            if regs[0] == product and not add_opcode.startswith("st"):
                break
    return pairs


def describe(body, tail):
    starts = {address for address, _, _ in body}
    counts = {name: sum(op == name for _, op, _ in body) for name in ("umlal.2d", "umull.2d", "add.2d", "eor3.16b")}
    calls = []
    vector_stack = []
    for address, op, operands in body:
        if op.startswith("bl") or op.startswith("br") or (op == "b" and operands != tail and
                (not operands.startswith("0x") or int(operands, 16) not in starts)):
            calls.append([hex(address), op, operands])
        if op.startswith(("ld", "st")) and STACK.search(operands) and VECTOR.search(operands.split("[", 1)[0]):
            vector_stack.append([hex(address), op, operands])
    return {"counts": counts, "product_to_add": product_pairs(body), "unexpected_calls": calls,
            "vector_stack_accesses": vector_stack, "vector_registers": sorted({int(x) for _, _, s in body for x in VECTOR.findall(s)})}


def inspect(text):
    common = Path(__file__).resolve().parent.parent / "apple-fixed-proof/inspect-native-fixed.py"
    spec = importlib.util.spec_from_file_location("native_assembly", common)
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    functions = parser.parse(text)
    graph = parser.calls(functions)
    arms = {}
    for prefix in ("", "split_"):
        name = "split" if prefix else "generic"
        reachable = parser.reachable(graph, f"_{prefix}yespower")
        mixers = {}
        for symbol, count, eor3, tail in zip(REFERENCE, EXPECTED, EOR3, TAILS, strict=True):
            label = f"_{prefix}{symbol}"
            facts = describe(functions.get(label, []), f"_{prefix}{tail}" if tail else "")
            expected = (0, count, count, eor3) if prefix else (count, 0, 0, eor3)
            facts["verified"] = label in reachable and tuple(facts["counts"].values()) == expected and (
                len(facts["product_to_add"]) == count if prefix else not facts["product_to_add"]) and (
                not facts["unexpected_calls"] and not facts["vector_stack_accesses"])
            mixers[label] = facts
        arms[name] = mixers
    verified = all(row["verified"] for mixers in arms.values() for row in mixers.values())
    return {"status": "verified" if verified else "codegen_only", "mixers": arms}


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
    print(f"Native split PWX evidence = {report['status']}")


if __name__ == "__main__":
    main()
