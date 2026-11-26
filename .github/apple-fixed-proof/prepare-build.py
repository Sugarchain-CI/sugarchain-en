#!/usr/bin/env python3
"""Build the standalone experiment from an unmodified pinned production source checkout."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

SOURCE = "9c502574b652804905d2533d51742ca91f694532"
TREE = "f44aa1b47f9701996046bbb396106f1d5c365e66"
VENDOR = "src/crypto/yespower-1.0.1"
INPUTS = (
    *(f"{VENDOR}/{name}" for name in (
        "yespower-opt.c", "yespower-platform.c", "yespower.h", "sha256.c", "sha256.h", "sha256-dispatch.h",
        "sysendian.h", "insecure_memzero.h",
    )),
    "src/primitives/block.h", "src/primitives/block.cpp",
)
HERE = Path(__file__).resolve().parent


def head(source, rev):
    return subprocess.check_output(["git", "-C", str(source), "rev-parse", rev], text=True, timeout=10).strip()


def exact(source, name):
    committed = subprocess.check_output(["git", "-C", str(source), "show", f"{SOURCE}:{name}"], timeout=10)
    disk = (source / name).read_bytes()
    if disk != committed:
        raise ValueError(f"Production input differs from the pinned commit: {name}")
    return disk


def render_params(header, implementation):
    number = lambda name: re.search(rf"inline constexpr uint32_t YESPOWER_SUGAR_{name}\{{(\d+)\}};", header).group(1)
    if number("VERSION") != "10" or "static_assert(YESPOWER_SUGAR_VERSION == YESPOWER_1_0)" not in implementation:
        raise ValueError("Expected the pinned version-one Sugar proof implementation")
    personalization = re.search(r'YESPOWER_SUGAR_PERSONALIZATION\[\]\s*=\s*("[^"\\]+")\s*;', header).group(1)
    return f'''#ifndef SUGAR_PARAMS_H
#define SUGAR_PARAMS_H
#define PROBE_VERSION YESPOWER_1_0
#define PROBE_N UINT32_C({number("N")})
#define PROBE_R UINT32_C({number("R")})
static const uint8_t probe_personalization[] = {personalization};
static const yespower_params_t probe_params = {{PROBE_VERSION, PROBE_N, PROBE_R,
    probe_personalization, sizeof(probe_personalization) - 1}};
#endif
'''



def function(text, pattern):
    matches = list(re.finditer(pattern, text, re.M))
    if len(matches) != 1:
        raise ValueError(f"Expected one original function matching {pattern}")
    start = matches[0].start()
    end = text.index("\n}", start) + len("\n}")
    return text[start:end]


def once(text, expected, replacement):
    if text.count(expected) != 1:
        raise ValueError(f"Expected one pinned source fragment: {expected}")
    return text.replace(expected, replacement, 1)


def inline_row(vendor, result_type, name):
    definition = f"static {result_type} {name}("
    original = function(vendor, rf"^{re.escape(definition)}")
    return once(original, definition, f"__attribute__((always_inline)) static inline {result_type} fixed_sugar_{name}(")


def generate_probe(vendor):
    mix = function(vendor, r"^static void smix\(")
    begin = mix.index("#if _YESPOWER_OPT_C_PASS_ == 1")
    seed = mix.index("\n\tsmix1(B, 1,", begin)
    version_one = mix[begin:seed].split("#else\n", 1)[1].split("#endif", 1)[0]
    if not version_one.startswith("\tuint32_t Nloop_rw = "):
        raise ValueError("Unexpected original version-one loop count")
    fixed_loop_count = version_one.replace("Nloop_rw", "Nloop").rstrip()
    rows = [inline_row(vendor, result, name) for result, name in (
        ("void", "blockmix"), ("uint32_t", "blockmix_xor"), ("uint32_t", "blockmix_xor_save"),
    )]
    first = function(vendor, r"^static void smix1\(")
    first = once(first, "static void smix1(uint8_t *B, size_t r, uint32_t N,\n"
                 "    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)\n{",
                 "__attribute__((noinline))\nstatic void fixed_sugar_smix1(uint8_t *B,\n"
                 "    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)\n{\n"
                 "    const size_t r = PROBE_R;\n    const uint32_t N = PROBE_N;")
    for name, count in (("blockmix", 3), ("blockmix_xor", 4)):
        if first.count(f"{name}(") != count:
            raise ValueError(f"Unexpected original {name} call graph")
        first = first.replace(f"{name}(", f"fixed_sugar_{name}(")
    phase = function(vendor, r"^static void smix2\(")
    phase = once(phase, "static void smix2(uint8_t *B, size_t r, uint32_t N, uint32_t Nloop,\n"
                 "    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)\n{",
                 "__attribute__((noinline))\nstatic void fixed_sugar_smix2(uint8_t *B,\n"
                 "    salsa20_blk_t *V, salsa20_blk_t *XY, pwxform_ctx_t *ctx)\n{\n"
                 "    const size_t r = PROBE_R;\n    const uint32_t N = PROBE_N;\n" + fixed_loop_count)
    if phase.count("blockmix_xor_save(") != 2:
        raise ValueError("Unexpected original row loop shape")
    phase = phase.replace("blockmix_xor_save(", "fixed_sugar_blockmix_xor_save(")
    # The loop-count code now belongs to the fixed phase. The generic copy
    # continues to compile both original version branches.
    mix = mix[:begin] + mix[seed + 1:]
    mix = once(mix, "smix1(B, r, N, V, XY, ctx);", "fixed_sugar_smix1(B, V, XY, ctx);")
    mix = once(mix, "smix2(B, r, N, Nloop_rw /* must be > 2 */, V, XY, ctx);", "fixed_sugar_smix2(B, V, XY, ctx);")
    legacy = mix.index("\n#if _YESPOWER_OPT_C_PASS_ == 1")
    mix = mix[:legacy] + "\n}"
    mix = once(mix, "static void smix(uint8_t *B, size_t r, uint32_t N,\n",
               "__attribute__((always_inline)) static inline void fixed_sugar_mix(uint8_t *B,\n")
    body = function(vendor, r"^int yespower\(")
    body = once(body, "int yespower(", "__attribute__((always_inline)) static inline int fixed_sugar_body(")
    body = once(body, "smix_1_0(B, r, N, V, XY, &ctx);", "fixed_sugar_mix(B, V, XY, &ctx);")
    return '\n\n'.join((*rows, first, phase, mix, body)) + '\n'


DISPATCH = """
int fixed_sugar_probe(yespower_local_t *local, const uint8_t *header, size_t header_bytes,
    const yespower_params_t *params, yespower_binary_t *proof)
{
    if (header_bytes != PROBE_HEADER_BYTES || params->version != PROBE_VERSION ||
        params->N != PROBE_N || params->r != PROBE_R || !params->pers ||
        params->perslen != sizeof(probe_personalization) - 1 ||
        memcmp(params->pers, probe_personalization, params->perslen)) {
        return yespower(local, header, header_bytes, params, proof);
    }
    return fixed_sugar_body(local, header, PROBE_HEADER_BYTES, &probe_params, proof);
}
"""

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--cflag", action="append", default=[])
    args = parser.parse_args()
    source, output = args.source.resolve(strict=True), args.output.resolve()
    if head(source, "HEAD") != SOURCE or head(source, "HEAD^{tree}") != TREE:
        parser.error("Expected the exact pinned product source worktree")
    if source == output or source in output.parents:
        parser.error("Build output must be outside the product checkout")
    pinned = {name: exact(source, name) for name in INPUTS}
    compiler = shutil.which(args.cc)
    if compiler is None:
        parser.error("Requested compiler is unavailable")
    output.mkdir(mode=0o700)
    for name, content in pinned.items():
        if name.startswith(f"{VENDOR}/"):
            (output / Path(name).name).write_bytes(content)
    vendor = pinned[f"{VENDOR}/yespower-opt.c"].decode()
    fixed_source = '#include "yespower-opt.c"\n#include "fixed-probe.h"\n#include "sugar-params.h"\n\n'
    (output / "fixed-sugar.c").write_text(fixed_source + generate_probe(vendor) + DISPATCH, encoding="utf-8")
    for name in ("fixed-probe.h", "fixed-yespower-probe.c", "probe-clock.h"):
        shutil.copyfile(HERE / name, output / name)
    (output / "sugar-params.h").write_text(render_params(pinned["src/primitives/block.h"].decode(), pinned["src/primitives/block.cpp"].decode()), encoding="utf-8")
    command = [compiler, "-O3", "-std=gnu11", "-Wall", "-Wextra", *args.cflag, "-pthread", "fixed-sugar.c", "sha256.c", "fixed-yespower-probe.c", "-o", "fixed_yespower_probe"]
    subprocess.run(command, cwd=output, check=True, timeout=120)
    receipt = {
        "source": SOURCE, "tree": TREE, "compiler": subprocess.check_output([compiler, "--version"], text=True, timeout=10).splitlines()[0],
        "compiler_arguments": command, "production_input_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in pinned.items()},
        "probe_sha256": hashlib.sha256((output / "fixed_yespower_probe").read_bytes()).hexdigest(),
    }
    (output / "build.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("Built exact-source standalone generic and fixed-parameter probe")


if __name__ == "__main__":
    main()
