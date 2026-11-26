"""Materialize three scope-limited variants from the pinned Apple baseline."""

from difflib import unified_diff
from pathlib import Path
from shutil import copytree
import sys


source = Path(sys.argv[1]) / "src/crypto/yespower-1.0.1"
work = Path(sys.argv[2])
variants_dir = work / "variants"
variants_dir.mkdir()
base = (source / "yespower-opt.c").read_text()
cut = base.index("#elif defined(YESPOWER_APPLE_NEON)\n\n#define PWXFORM_SIMD")
end = base.index("#else /* !defined(__SSE2__) */", cut)
section = base[cut:end]

old_unzip = '''\tuint32x2_t lo = vget_low_u32(vuzp1q_u32(x, x)); \\
\tuint32x2_t hi = vget_low_u32(vuzp2q_u32(x, x)); \\
'''
new_unzip = '''\tuint32x4_t even_words, odd_words; \\
\t/* Prevent Clang from lowering the low halves to EXT plus two ZIPs. */ \\
\t__asm__("uzp1 %0.4s, %2.4s, %2.4s\\n\\t" \\
\t    "uzp2 %1.4s, %2.4s, %2.4s" \\
\t    : "=&w"(even_words), "=w"(odd_words) : "w"(x)); \\
\tuint32x2_t lo = vget_low_u32(even_words); \\
\tuint32x2_t hi = vget_low_u32(odd_words); \\
'''
old_load = '''\tuint64_t offset = vgetq_lane_u64(vreinterpretq_u64_u32(x), 0) & Smask2; \\
\tconst uint64_t *p0 = (const uint64_t *)(S0 + (uint32_t)offset); \\
\tconst uint64_t *p1 = (const uint64_t *)(S1 + (offset >> 32)); \\
'''
new_load = '''\tconst uint64_t lane = vgetq_lane_u64(vreinterpretq_u64_u32(x), 0); \\
\t/* Each table entry holds two 64-bit words. This exposes scaled loads. */ \\
\tconst uint32_t index_mask = (uint32_t)Smask2 >> 4; \\
\tconst size_t index0 = (lane >> 4) & index_mask; \\
\tconst size_t index1 = (lane >> 36) & index_mask; \\
\tconst uint64_t *p0 = (const uint64_t *)S0 + 2 * index0; \\
\tconst uint64_t *p1 = (const uint64_t *)S1 + 2 * index1; \\
'''
assert section.count(old_unzip) == section.count(old_load) == 1
variants = {
    "baseline": section,
    "unzip": section.replace(old_unzip, new_unzip),
    "index": section.replace(old_load, new_load),
    "combined": section.replace(old_unzip, new_unzip).replace(old_load, new_load),
}
file = "src/crypto/yespower-1.0.1/yespower-opt.c"
for name, body in variants.items():
    variant_dir = variants_dir / name
    copytree(source, variant_dir)
    updated = base[:cut] + body + base[end:]
    (variant_dir / "yespower-opt.c").write_text(updated)
    if name != "baseline":
        patch = "".join(unified_diff(base.splitlines(keepends=True), updated.splitlines(keepends=True),
                                     fromfile=f"a/{file}", tofile=f"b/{file}"))
        (work / "evidence" / f"apple-pwx-{name}.patch").write_text(patch)
