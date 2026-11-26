/* Standalone experiment, injected only in a private copy of the exact source. */
#include "paired-probe.h"
#include "sugar-params.h"

struct pair_smix_state {
    uint8_t *B;
    salsa20_blk_t *V;
    salsa20_blk_t *XY;
    pwxform_ctx_t ctx;
    uint8_t sha256[32];
};

static void lane_result(paired_probe_lane *lane, int result)
{
    lane->result = result;
    lane->error_number = result ? errno : 0;
    if (result)
        memset(&lane->proof, 0xff, sizeof(lane->proof));
}

static void single_lane(paired_probe_lane *lane)
{
    int result = yespower(lane->local, lane->header, lane->header_bytes, lane->params, &lane->proof);
    lane_result(lane, result);
}

static int paired_params(const paired_probe_lane *lane)
{
    const yespower_params_t *params = lane->params;
    return lane->header_bytes == PROBE_HEADER_BYTES && params->version == PROBE_VERSION &&
        params->N == PROBE_N && params->r == PROBE_R && params->pers &&
        params->perslen == sizeof(probe_personalization) - 1 &&
        memcmp(params->pers, probe_personalization, params->perslen) == 0;
}

/* Preserve the production 1.0 prefix with exact source-derived Sugar parameters. */
static int prepare_lane(paired_probe_lane *lane, struct pair_smix_state *state)
{
    const size_t B_size = (size_t)128 * PROBE_R;
    const size_t V_size = B_size * PROBE_N;
    const size_t XY_size = B_size + 64;
    const size_t table_bytes = Swidth_to_Sbytes1(Swidth_1_0);
    const size_t Sbytes = 3 * table_bytes;
    const size_t need = B_size + V_size + XY_size + Sbytes;
    if (lane->local->aligned_size < need &&
        (free_region(lane->local) || !alloc_region(lane->local, need))) {
        lane_result(lane, -1);
        return -1;
    }
    state->B = lane->local->aligned;
    state->V = (salsa20_blk_t *)(state->B + B_size);
    state->XY = (salsa20_blk_t *)((uint8_t *)state->V + V_size);
    uint8_t *S = (uint8_t *)state->XY + XY_size;
    state->ctx.Sbytes = Sbytes;
    state->ctx.S0 = S;
    state->ctx.S1 = S + table_bytes;
    state->ctx.S2 = S + 2 * table_bytes;
    state->ctx.w = 0;

    SHA256_Buf(lane->header, lane->header_bytes, state->sha256);
    PBKDF2_SHA256(state->sha256, sizeof(state->sha256), lane->params->pers,
        lane->params->perslen, 1, state->B, 128);
    memcpy(state->sha256, state->B, sizeof(state->sha256));
    smix1_1_0(state->B, 1, Sbytes / 128, (salsa20_blk_t *)state->ctx.S0, state->XY, NULL);
    smix1_1_0(state->B, PROBE_R, PROBE_N, state->V, state->XY, &state->ctx);
    return 0;
}

static void shuffle_lane(struct pair_smix_state *state, int decode)
{
    salsa20_blk_t *const tmp = &state->XY[2 * PROBE_R];
    for (size_t i = 0; i < 2 * PROBE_R; ++i) {
        salsa20_blk_t *const bytes = (salsa20_blk_t *)&state->B[i * 64];
        salsa20_blk_t *const vector = &state->XY[i];
        if (decode) {
            for (size_t k = 0; k < 16; ++k)
                tmp->w[k] = le32dec(&bytes->w[k]);
            salsa20_simd_shuffle(tmp, vector);
        } else {
            for (size_t k = 0; k < 16; ++k)
                le32enc(&tmp->w[k], vector->w[k]);
            salsa20_simd_unshuffle(tmp, bytes);
        }
    }
}

static inline void hint_known_row(const salsa20_blk_t *row)
{
    __builtin_prefetch(&row[2 * PROBE_R - 1], 0, 1);
    __builtin_prefetch(&row[0], 0, 1);
}

static inline void start_mixed_row(salsa20_blk_t *rolling, const salsa20_blk_t *last_x,
    const salsa20_blk_t *last_v)
{
    DECL_X
    XOR_X_2(*last_x, *last_v)
    WRITE_X(*rolling)
}

/* The same existing operations as blockmix_xor_save's 64-byte sequence. */
__attribute__((always_inline))
static inline uint32_t mix_subblock(salsa20_blk_t *restrict rolling, salsa20_blk_t *restrict x,
    salsa20_blk_t *restrict v, pwxform_ctx_t *restrict ctx, int final)
{
    uint8_t *S0 = ctx->S0, *S1 = ctx->S1, *S2 = ctx->S2;
    size_t w = ctx->w;
    DECL_X
    DECL_Y
    DECL_SMASK2REG
    READ_X(*rolling)
    XOR_X_WRITE_XOR_Y_2(*v, *x)
    PWXFORM
    ctx->S0 = S0;
    ctx->S1 = S1;
    ctx->S2 = S2;
    ctx->w = w;
    if (final) {
        SALSA20(*x)
    } else {
        WRITE_X(*x)
        WRITE_X(*rolling)
    }
    return INTEGERIFY;
}

/* Keep this symbol for inspection. Flattening is local to this experiment. */
__attribute__((noinline, flatten))
static void paired_smix2_rows(salsa20_blk_t *restrict x0, salsa20_blk_t *restrict v0,
    pwxform_ctx_t *restrict c0, salsa20_blk_t *restrict x1, salsa20_blk_t *restrict v1,
    pwxform_ctx_t *restrict c1, int cache_hints)
{
    const size_t s = 2 * PROBE_R;
    const uint32_t rounds = ((PROBE_N + 2) / 3 + 1) & ~(uint32_t)1;
    uint32_t j0 = integerify(x0, PROBE_R) & (PROBE_N - 1);
    uint32_t j1 = integerify(x1, PROBE_R) & (PROBE_N - 1);
    for (uint32_t i = 0; i < rounds; ++i) {
        salsa20_blk_t *const row0 = &v0[j0 * s];
        salsa20_blk_t *const row1 = &v1[j1 * s];
        salsa20_blk_t rolling[2];
        if (cache_hints)
            hint_known_row(row1);
        start_mixed_row(&rolling[0], &x0[s - 1], &row0[s - 1]);
        start_mixed_row(&rolling[1], &x1[s - 1], &row1[s - 1]);
        /* Each outer iteration executes both independent lanes per subblock. */
        for (size_t block = 0; block + 1 < s; ++block) {
            mix_subblock(&rolling[0], &x0[block], &row0[block], c0, 0);
            mix_subblock(&rolling[1], &x1[block], &row1[block], c1, 0);
        }
        j0 = mix_subblock(&rolling[0], &x0[s - 1], &row0[s - 1], c0, 1) & (PROBE_N - 1);
        if (cache_hints && i + 1 < rounds)
            hint_known_row(&v0[j0 * s]);
        j1 = mix_subblock(&rolling[1], &x1[s - 1], &row1[s - 1], c1, 1) & (PROBE_N - 1);
    }
}

static void finish_lane(paired_probe_lane *lane, const struct pair_smix_state *state)
{
    HMAC_SHA256_Buf(state->B + 128 * PROBE_R - 64, 64,
        state->sha256, sizeof(state->sha256), (uint8_t *)&lane->proof);
    lane_result(lane, 0);
}

void paired_probe_hash(paired_probe_lane lanes[2], int cache_hints)
{
    if (lanes[0].local == lanes[1].local || !paired_params(&lanes[0]) || !paired_params(&lanes[1])) {
        single_lane(&lanes[0]);
        single_lane(&lanes[1]);
        return;
    }

    struct pair_smix_state state[2];
    int prepared[2];
    for (size_t i = 0; i < 2; ++i)
        prepared[i] = prepare_lane(&lanes[i], &state[i]) == 0;
    if (prepared[0] && prepared[1]) {
        shuffle_lane(&state[0], 1);
        shuffle_lane(&state[1], 1);
        paired_smix2_rows(state[0].XY, state[0].V, &state[0].ctx,
            state[1].XY, state[1].V, &state[1].ctx, cache_hints);
        shuffle_lane(&state[0], 0);
        shuffle_lane(&state[1], 0);
    } else {
        const uint32_t rounds = ((PROBE_N + 2) / 3 + 1) & ~(uint32_t)1;
        for (size_t i = 0; i < 2; ++i) {
            if (prepared[i])
                smix2_1_0(state[i].B, PROBE_R, PROBE_N, rounds, state[i].V, state[i].XY, &state[i].ctx);
        }
    }
    for (size_t i = 0; i < 2; ++i) {
        if (prepared[i])
            finish_lane(&lanes[i], &state[i]);
    }
}
