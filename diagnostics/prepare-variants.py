#!/usr/bin/env python3
import pathlib
import shutil
import sys

source = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
base = (source / 'yespower-opt.c').read_text()
assert '#define YESPOWER_APPLE_NEON' in base
unzip = '''\tuint32x2_t lo = vget_low_u32(vuzp1q_u32(x, x)); \\
\tuint32x2_t hi = vget_low_u32(vuzp2q_u32(x, x)); \\
'''
narrow = '''\tuint32x2_t lo = vmovn_u64(vreinterpretq_u64_u32(x)); \\
\tuint32x2_t hi = vshrn_n_u64(vreinterpretq_u64_u32(x), 32); \\
'''
old_prefetch = '#define PREFETCH(x, hint) _mm_prefetch((const char *)(x), (hint));\n#else\n#undef PREFETCH'
new_prefetch = '#define PREFETCH(x, hint) _mm_prefetch((const char *)(x), (hint));\n#elif defined(YESPOWER_APPLE_NEON)\n#define PREFETCH(x, hint) __builtin_prefetch((x), 0, 3);\n#else\n#undef PREFETCH'
assert base.count(unzip) == base.count(old_prefetch) == 1
block = '''\tx = vreinterpretq_u32_u64(veorq_u64(vaddq_u64(vmull_u32(lo, hi), \\
\t    vld1q_u64(p0)), vld1q_u64(p1))); \\
'''
assert base.count(block) == 1
scalar = '''\tuint64_t a = vgetq_lane_u64(vreinterpretq_u64_u32(x), 0); \\
\tuint64_t b = vgetq_lane_u64(vreinterpretq_u64_u32(x), 1); \\
\ta = ((uint64_t)(uint32_t)a * (a >> 32) + p0[0]) ^ p1[0]; \\
\tb = ((uint64_t)(uint32_t)b * (b >> 32) + p0[1]) ^ p1[1]; \\
\tx = vreinterpretq_u32_u64(vcombine_u64(vcreate_u64(a), vcreate_u64(b))); \\
'''
variants = {
    'neon': base,
    'narrow': base.replace(unzip, narrow),
    'prefetch': base.replace(old_prefetch, new_prefetch),
    'narrow-prefetch': base.replace(unzip, narrow).replace(old_prefetch, new_prefetch),
    'scalar-pwx': base.replace(unzip, '').replace(block, scalar),
}
for name, body in variants.items():
    path = out / name
    shutil.copytree(source, path)
    (path / 'yespower-opt.c').write_text(body)
print('Prepared ' + ', '.join(variants))
