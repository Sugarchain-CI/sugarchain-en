// Copyright (c) 2026 The Sugarchain En developers
// Distributed under the MIT software license, see the accompanying file COPYING.

#if defined(__APPLE__) && defined(__aarch64__)
// Build the same implementation with independent PWX multiply and add operations.
// Its callers continue to own and initialize the same yespower_local_t scratch.
#define SUGARCHAIN_YESPOWER_SPLIT_PWX
#define yespower yespower_presync_split
#define yespower_init_local yespower_presync_init_local
#define yespower_free_local yespower_presync_free_local
#define yespower_tls yespower_presync_tls
#include "yespower-opt.c"
#endif
