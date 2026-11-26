#!/usr/bin/env python3
"""Check the ARM64 BlockMix encodings in the complete Mach-O executable."""

import argparse
import bisect
import json
from pathlib import Path
import struct


FUNCTIONS = (b"_blockmix_xor_1_0", b"_blockmix_xor_save_1_0")


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


def blockmix_words(data):
    magic, cpu, _, _, commands = struct.unpack_from("<5I", data)
    if magic != 0xfeedfacf or cpu != 0x0100000c:
        raise ValueError("Expected a thin ARM64 Mach-O executable")
    text, symbol_table, function_table, text_base = None, None, None, None
    offset, section_index = 32, 0
    for _ in range(commands):
        kind, size = struct.unpack_from("<II", data, offset)
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
        elif kind == 2:  # LC_SYMTAB
            symbol_table = struct.unpack_from("<4I", data, offset + 8)
        elif kind == 0x26:  # LC_FUNCTION_STARTS
            function_table = struct.unpack_from("<2I", data, offset + 8)
        offset += size
    if text is None or symbol_table is None or function_table is None or text_base is None:
        raise ValueError("Mach-O text, symbols or function-start table is missing")

    text_address, text_length, text_file, text_section = text
    starts_file, starts_size = function_table
    starts = list(function_starts(data[starts_file:starts_file + starts_size], text_base))
    starts.append(text_address + text_length)
    symbols_file, count, strings_file, _ = symbol_table
    addresses = {}
    for offset in range(symbols_file, symbols_file + count * 16, 16):
        name_offset, kind, section, _, address = struct.unpack_from("<IBBHQ", data, offset)
        if kind & 0xe0 or kind & 0x0e != 0x0e or section != text_section:
            continue
        first = strings_file + name_offset
        name = data[first:data.index(b"\0", first)].split(b".llvm.", 1)[0]
        if name in FUNCTIONS:
            addresses[name] = address

    for name in FUNCTIONS:
        if name not in addresses:
            raise ValueError(f"Missing BlockMix symbol {name.decode()}")
        start = addresses[name]
        index = bisect.bisect_left(starts, start)
        if index >= len(starts) - 1 or starts[index] != start:
            raise ValueError(f"Missing entry point for {name.decode()}")
        end = starts[index + 1]
        first, last = text_file + start - text_address, text_file + end - text_address
        yield name.decode(), (word for (word,) in struct.iter_unpack("<I", data[first:last]))


def prefetch(word):
    # A64 PRFM immediate, register offset and literal forms.
    return (word & 0xffc00000 == 0xf9800000 or
            word & 0xffe04c00 == 0xf8a04800 or
            word & 0xff000000 == 0xd8000000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("kind", choices=("baseline", "prefetch"))
    arguments = parser.parse_args()
    results = {}
    for name, words in blockmix_words(arguments.path.read_bytes()):
        eor3, prfm = 0, 0
        for word in words:
            eor3 += word & 0xffe08000 == 0xce000000
            prfm += prefetch(word)
        results[name] = {"eor3": eor3, "prfm": prfm}
    print(json.dumps(results, indent=2), flush=True)
    for name, counts in results.items():
        if counts["eor3"] == 0 or bool(counts["prfm"]) != (arguments.kind == "prefetch"):
            raise SystemExit(f"Unexpected EOR3 or PRFM instruction count in {name}")


if __name__ == "__main__":
    main()
