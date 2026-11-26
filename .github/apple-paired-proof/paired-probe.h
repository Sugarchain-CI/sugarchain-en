#ifndef PAIRED_PROBE_H
#define PAIRED_PROBE_H

#include "yespower.h"

#define PROBE_HEADER_BYTES 80

typedef struct {
    yespower_local_t *local;
    const uint8_t *header;
    size_t header_bytes;
    const yespower_params_t *params;
    yespower_binary_t proof;
    int result;
    int error_number;
} paired_probe_lane;

void paired_probe_hash(paired_probe_lane lanes[2], int cache_hints);

#endif
