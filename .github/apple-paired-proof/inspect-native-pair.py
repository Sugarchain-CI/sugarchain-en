#!/usr/bin/env python3
"""Inspect the emitted paired SMix core in the native Mach-O executable."""

import argparse
import bisect
from collections import Counter
import json
from pathlib import Path
import re
import struct


FUNCTIONS = (b"_paired_smix2_rows",)


def function_starts(encoded, address):
    delta, shift = 0, 0
    for byte in encoded:
        delta |= (byte & 0x7f) << shift
        if byte & 0x80:
            shift += 7
            continue
        if delta == 0:
            break
        address += delta
        yield address
        delta, shift = 0, 0


def arm64_macho_text(data):
    magic, cpu, _, _, commands = struct.unpack_from("<5I", data)
    if magic != 0xfeedfacf or cpu != 0x0100000c:
        raise ValueError("Expected a thin ARM64 Mach-O executable")
    text, symbol_table, function_table, text_base = None, None, None, None
    stubs = []
    offset, section_index = 32, 0
    for _ in range(commands):
        kind, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            raise ValueError("Invalid Mach-O load command")
        if kind == 0x19:  # LC_SEGMENT_64
            segment, address = struct.unpack_from("<16sQ", data, offset + 8)
            if segment.rstrip(b"\0") == b"__TEXT":
                text_base = address
            sections, = struct.unpack_from("<I", data, offset + 64)
            for index in range(sections):
                entry = offset + 72 + index * 80
                name, segment, address, length, location = struct.unpack_from("<16s16sQQI", data, entry)
                section_index += 1
                if (segment.rstrip(b"\0"), name.rstrip(b"\0")) == (b"__TEXT", b"__text"):
                    text = (address, length, location, section_index)
                section_flags, _, stub_stride = struct.unpack_from("<3I", data, entry + 64)
                if section_flags & 0xff == 0x8:  # S_SYMBOL_STUBS
                    if not stub_stride or length % stub_stride:
                        raise ValueError("Invalid Mach-O symbol stub section")
                    stubs.append((address, address + length, stub_stride))
        elif kind == 2:  # LC_SYMTAB
            symbol_table = struct.unpack_from("<4I", data, offset + 8)
        elif kind == 0x26:  # LC_FUNCTION_STARTS
            function_table = struct.unpack_from("<2I", data, offset + 8)
        offset += size
    if text is None or symbol_table is None or function_table is None or text_base is None:
        raise ValueError("Mach-O text, symbols or function-start table is missing")

    text_address, text_length, text_file, text_section = text
    starts_file, starts_size = function_table
    if text_file + text_length > len(data) or starts_file + starts_size > len(data):
        raise ValueError("Mach-O text or function-start data lies outside the executable")
    starts = list(function_starts(data[starts_file:starts_file + starts_size], text_base))
    starts.append(text_address + text_length)
    symbols_file, count, strings_file, _ = symbol_table
    addresses = {}
    for offset in range(symbols_file, symbols_file + count * 16, 16):
        name_offset, kind, section, _, address = struct.unpack_from("<IBBHQ", data, offset)
        if kind & 0xe0 or kind & 0x0e != 0x0e or section != text_section:
            continue
        first = strings_file + name_offset
        name = data[first:data.index(b"\0", first)].decode().split(".llvm.", 1)[0]
        addresses.setdefault(name, set()).add(address)
    return text_address, data[text_file:text_file + text_length], starts, addresses, stubs


def pair_core_words(data):
    text_address, text, starts, addresses, _ = arm64_macho_text(data)
    for symbol in FUNCTIONS:
        name = symbol.decode()
        slots = addresses.get(name, set())
        if len(slots) != 1:
            raise ValueError(f"Missing or ambiguous paired SMix symbol {name}")
        start, = slots
        index = bisect.bisect_left(starts, start)
        if index >= len(starts) - 1 or starts[index] != start:
            raise ValueError(f"Missing entry point for {name}")
        end = starts[index + 1]
        first, last = start - text_address, end - text_address
        yield name, start, (word for (word,) in struct.iter_unpack("<I", text[first:last]))


def instruction_counts(start, words, assembly):
    results = {"instruction_words": 0, "stack_addressed_memory_words": 0,
               "compiler_guard_calls": [], "unexpected_calls": []}
    for offset, word in enumerate(words):
        results["instruction_words"] += 1
        if word & 0xfc000000 == 0x94000000 or word & 0xfffffc1f == 0xd63f0000:  # BL or BLR
            address = start + offset * 4
            instruction = assembly.get(address, "")
            if re.search(r"___(?:stack_chk_fail|chkstk_darwin)\b", instruction):
                results["compiler_guard_calls"].append(hex(address))
            else:
                results["unexpected_calls"].append({"address": hex(address), "text": instruction})
        # Includes stack locals, save/restore and possible spills. These are
        # instruction words, not dynamically executed operations.
        results["stack_addressed_memory_words"] += (
            word & 0x3a000000 in (0x28000000, 0x38000000) and ((word >> 5) & 31) == 31
        )
    return results


def signed(value, bits):
    return (value ^ (1 << (bits - 1))) - (1 << (bits - 1))


def branch_target(index, word):
    if word & 0xfc000000 == 0x14000000:  # B
        return index + signed(word & 0x03ffffff, 26)
    if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:  # B.cond or CBZ/CBNZ
        return index + signed((word >> 5) & 0x7ffff, 19)
    if word & 0x7e000000 == 0x36000000:  # TBZ/TBNZ
        return index + signed((word >> 5) & 0x3fff, 14)
    return None


def stack_vector_counts(words, has_frame_pointer):
    counts = {"sp_vector_memory_words": 0, "frame_pointer_vector_memory_words": 0}
    for word in words:
        if word & 0x3e000000 not in (0x2c000000, 0x3c000000):
            continue  # Ignore literals and non-vector memory instructions.
        base = (word >> 5) & 31
        counts["sp_vector_memory_words"] += base == 31
        counts["frame_pointer_vector_memory_words"] += has_frame_pointer and base == 29
    return counts


def loop_metrics(words):
    advances = Counter()
    q_store_bases = Counter()
    products = 0
    for word in words:
        base, dest = (word >> 5) & 31, word & 31
        products += word & 0xbfe0fc00 in (0x2ea0c000, 0x2ea08000)  # UMULL[2] and UMLAL[2], 2x32 to 2x64.
        if base == 31:
            continue
        if word & 0xffc00000 == 0x91000000 and base == dest:  # ADD Xn, Xn, immediate.
            advances[base] += (word >> 10) & 0xfff
        if word & 0xfe400000 == 0xac000000:  # STP of Q registers.
            q_store_bases[base] += 32
            if (word >> 23) & 3 in (1, 3):
                advances[base] += signed((word >> 15) & 0x7f, 7) * 16
        if word & 0xffc00000 == 0x3d800000 or word & 0xffe00c00 == 0x3c800000:  # STR Q, immediate.
            q_store_bases[base] += 16
        if word & 0xffe00400 == 0x3c800400:  # STR Q, pre/post-indexed.
            q_store_bases[base] += 16
            advances[base] += signed((word >> 12) & 0x1ff, 9)
    witness = sorted(base for base, size in q_store_bases.items() if size == 64 and advances[base] == 64)
    return {
        "pwxf_unsigned_widening_products": products,
        "vector_store_base_bytes": {f"x{base}": size for base, size in sorted(q_store_bases.items())},
        "vector_store_base_advances": {f"x{base}": advances[base] for base in sorted(q_store_bases)},
        "subblock_stream_witnesses": [f"x{base}" for base in witness],
        "has_two_subblock_shape": products == 24 and len(witness) == 4,
    }


def inner_backedges(start, words):
    backedges = []
    for i, word in enumerate(words):
        target = branch_target(i, word)
        if target is not None and 0 <= target < i:
            backedges.append((target, i))
    leaves = [(head, tail) for head, tail in backedges if not any(
        head <= a and b <= tail and (a, b) != (head, tail) for a, b in backedges
    )]
    frame_pointer = any(word & 0xffc003ff == 0x910003fd for word in words[:32])  # ADD X29, SP, immediate.
    loops = []
    for head, tail in leaves:
        body = words[head:tail + 1]
        loops.append({"start": hex(start + head * 4), "backedge": hex(start + tail * 4),
                      "instruction_words": len(body), **loop_metrics(body),
                      **stack_vector_counts(body, frame_pointer)})
    matched = [(head, tail) for (head, tail), report in zip(leaves, loops, strict=True) if report["has_two_subblock_shape"]]
    result = {"inner_backedges": loops, "explicit_frame_pointer": frame_pointer,
              "paired_inner_loop_witness_count": len(matched)}
    if len(matched) == 1:
        head, tail = matched[0]
        result["outside_paired_inner_loop_vector_memory"] = stack_vector_counts(words[:head] + words[tail + 1:], frame_pointer)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--disassembly", type=Path, required=True)
    arguments = parser.parse_args()
    assembly = {int(match[1], 16): match[2] for match in re.finditer(
        r"^\s*(?:0x)?([0-9a-fA-F]{8,16})\s+([^\n]+)", arguments.disassembly.read_text(), re.M
    )}
    results = {}
    for name, start, source in pair_core_words(arguments.path.read_bytes()):
        words = list(source)
        results[name] = {**instruction_counts(start, words, assembly), **inner_backedges(start, words)}
    print(json.dumps(results, indent=2), flush=True)
    for name, counts in results.items():
        if counts["instruction_words"] == 0 or counts["unexpected_calls"]:
            raise SystemExit(f"Candidate emits out-of-line calls or has an empty paired SMix core: {name}")
        if counts["paired_inner_loop_witness_count"] != 1:
            raise SystemExit(f"Code generation only. The paired subblock loop shape is unconfirmed: {name}")


if __name__ == "__main__":
    main()
