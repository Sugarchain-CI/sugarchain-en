#!/usr/bin/env python3
"""Require the fused control and the independent native product/add sequences."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct


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


def describe(body, branches, tail):
    instructions = {address for address, _, _ in body}
    counts = {name: sum(op == name for _, op, _ in body) for name in ("umlal.2d", "umull.2d", "add.2d", "eor3.16b")}
    calls = []
    vector_stack = []
    for address, kind, target in branches:
        if kind != "branch" or (target not in instructions and target != tail):
            calls.append([hex(address), kind, hex(target) if target is not None else None])
    for address, op, operands in body:
        if op.startswith(("ld", "st")) and STACK.search(operands) and VECTOR.search(operands.split("[", 1)[0]):
            vector_stack.append([hex(address), op, operands])
    return {"counts": counts, "product_to_add": product_pairs(body), "unexpected_calls": calls,
            "vector_stack_accesses": vector_stack, "vector_registers": sorted({int(x) for _, _, s in body for x in VECTOR.findall(s)})}


def load_tool(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    parser = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser)
    return parser


def instructions_by_address(text, decoder):
    instructions = {}
    for line in text.splitlines():
        if match := decoder.fullmatch(line):
            address, opcode, operands = int(match[1], 16), match[2], match[3]
            if address in instructions:
                raise ValueError(f"Duplicate disassembly address {hex(address)}")
            instructions[address] = (address, opcode, operands)
    return instructions


def branch_records(text_address, raw, starts, disassembly, reader):
    records = {}
    for start, end in zip(starts, starts[1:]):
        if not text_address <= start < end <= text_address + len(raw) or (start | end) & 3:
            raise ValueError("Invalid linked function range")
        branches = []
        for index, (word,) in enumerate(struct.iter_unpack("<I", raw[start - text_address:end - text_address])):
            address = start + index * 4
            if word & 0xfc000000 == 0x94000000:  # BL
                branches.append((address, "call", address + reader.signed(word & 0x03ffffff, 26) * 4))
            elif (target := reader.branch_target(index, word)) is not None:  # B, B.cond, CB*, TB*
                branches.append((address, "branch", start + target * 4))
            elif word & 0xfffffc1f in (0xd61f0000, 0xd63f0000) or disassembly.get(address, (None, "", ""))[1] in (
                    "br", "blr", "braa", "brab", "braaz", "brabz", "blraa", "blrab", "blraaz", "blrabz"):
                branches.append((address, "indirect", None))
        records[start] = (end, branches)
    return records


def reachable_from(entry, records, stubs):
    seen = set()
    unresolved = []
    pending = [entry]
    while pending:
        start = pending.pop()
        if start in seen:
            continue
        seen.add(start)
        end, branches = records[start]
        for address, kind, target in branches:
            if kind == "branch" and start <= target < end:
                continue
            if target in records:
                pending.append(target)
            elif target is None or not any(a <= target < b and (target - a) % stride == 0 for a, b, stride in stubs):
                unresolved.append([hex(address), kind, hex(target) if target is not None else None])
    return seen, unresolved


def inspect(text, binary):
    common = Path(__file__).resolve().parent.parent
    parser = load_tool(common / "apple-fixed-proof/inspect-native-fixed.py")
    reader = load_tool(common / "apple-paired-proof/inspect-native-pair.py")
    address, raw, starts, symbols, stubs = reader.arm64_macho_text(binary)
    disassembly = instructions_by_address(text, parser.INSTRUCTION)
    records = branch_records(address, raw, starts, disassembly, reader)

    def unique(name):
        addresses = symbols.get(name, set())
        if len(addresses) != 1 or next(iter(addresses)) not in records:
            raise ValueError(f"Expected one linked function start for {name}")
        return next(iter(addresses))

    entries = {prefix: unique(f"_{prefix}yespower") for prefix in ("", "split_")}
    hot = {prefix: {symbol: unique(f"_{prefix}{symbol}") for symbol in REFERENCE} for prefix in entries}
    if len(set(entries.values()) | {addr for group in hot.values() for addr in group.values()}) != 8:
        raise ValueError("Proof entries or hot scopes unexpectedly share an address")
    arms = {}
    for prefix in ("", "split_"):
        name = "split" if prefix else "generic"
        reachable, unresolved = reachable_from(entries[prefix], records, stubs)
        opposite = "" if prefix else "split_"
        cross_arm = sorted(hex(addr) for addr in (reachable & (set(hot[opposite].values()) | {entries[opposite]})))
        mixers = {}
        for symbol, count, eor3, tail in zip(REFERENCE, EXPECTED, EOR3, TAILS, strict=True):
            label = f"_{prefix}{symbol}"
            start = hot[prefix][symbol]
            end, branches = records[start]
            body = [disassembly[pc] for pc in range(start, end, 4) if pc in disassembly]
            complete = len(body) == (end - start) // 4
            tail_address = unique(f"_{prefix}{tail}") if tail else None
            facts = describe(body, branches, tail_address)
            expected = (0, count, count, eor3) if prefix else (count, 0, 0, eor3)
            facts["start"] = hex(start)
            facts["tail_address"] = hex(tail_address) if tail_address is not None else None
            facts["complete_disassembly"] = complete
            facts["verified"] = start in reachable and complete and tuple(facts["counts"].values()) == expected and (
                len(facts["product_to_add"]) == count if prefix else not facts["product_to_add"]) and (
                not facts["unexpected_calls"] and not facts["vector_stack_accesses"])
            mixers[label] = facts
        arms[name] = {"entry": hex(entries[prefix]), "unresolved_branches": unresolved, "cross_arm_hot_addresses": cross_arm,
                      "mixers": mixers, "verified": not unresolved and not cross_arm and all(row["verified"] for row in mixers.values())}
    return {"status": "verified" if all(arm["verified"] for arm in arms.values()) else "codegen_only", "arms": arms}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("disassembly", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.disassembly.read_bytes()
    binary = args.binary.read_bytes()
    try:
        report = inspect(data.decode(), binary)
    except (ValueError, struct.error) as error:
        report = {"status": "codegen_only", "error": str(error)}
    report.update(disassembly_sha256=hashlib.sha256(data).hexdigest(), binary_sha256=hashlib.sha256(binary).hexdigest())
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(f"Native split PWX evidence = {report['status']}")


if __name__ == "__main__":
    main()
