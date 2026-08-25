// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// The CSPRNG TweetNaCl requires the application to supply: tweetnacl.c declares
// `extern void randombytes(u8*, u64)` and never defines it. fex::crypto::random_bytes
// forwards here as well, so there is a single entropy source for the whole program.
//
// Failure is fatal by design: silently continuing with unseeded key material is worse
// than aborting.

#include <stdlib.h>

#ifdef _WIN32

#include <windows.h>
#include <bcrypt.h>

void randombytes(unsigned char* x, unsigned long long xlen) {
    if (BCryptGenRandom(NULL, x, (ULONG)xlen, BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) abort();
}

#else

#include <unistd.h>
#ifdef __APPLE__
#include <sys/random.h> // getentropy lives here on Darwin, in <unistd.h> elsewhere
#endif

void randombytes(unsigned char* x, unsigned long long xlen) {
    while (xlen != 0) {
        const size_t n = xlen < 256 ? (size_t)xlen : 256; // getentropy caps at 256 bytes
        if (getentropy(x, n) != 0) abort();
        x += n;
        xlen -= n;
    }
}

#endif
