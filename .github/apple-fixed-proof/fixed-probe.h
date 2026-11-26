#ifndef FIXED_PROBE_H
#define FIXED_PROBE_H
#include "yespower.h"
#define PROBE_HEADER_BYTES 80
int fixed_sugar_probe(yespower_local_t *local, const uint8_t *header, size_t header_bytes,
    const yespower_params_t *params, yespower_binary_t *proof);
#endif
