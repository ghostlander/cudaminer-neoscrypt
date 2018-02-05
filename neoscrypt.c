/*
 * Copyright (c) 2009 Colin Percival, 2011 ArtForz
 * Copyright (c) 2012 Andrew Moon (floodyberry)
 * Copyright (c) 2012 Samuel Neves <sneves@dei.uc.pt>
 * Copyright (c) 2014-2016 John Doering <ghostlander@phoenixcoin.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "neoscrypt.h"


/* Salsa20, rounds must be a multiple of 2 */
static void neoscrypt_salsa(uint *X, uint rounds) {
    uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, t;

    x0 = X[0];   x1 = X[1];   x2 = X[2];   x3 = X[3];
    x4 = X[4];   x5 = X[5];   x6 = X[6];   x7 = X[7];
    x8 = X[8];   x9 = X[9];  x10 = X[10]; x11 = X[11];
   x12 = X[12]; x13 = X[13]; x14 = X[14]; x15 = X[15];

#define quarter(a, b, c, d) \
    t = a + d; t = ROTL32(t,  7); b ^= t; \
    t = b + a; t = ROTL32(t,  9); c ^= t; \
    t = c + b; t = ROTL32(t, 13); d ^= t; \
    t = d + c; t = ROTL32(t, 18); a ^= t;

    for(; rounds; rounds -= 2) {
        quarter( x0,  x4,  x8, x12);
        quarter( x5,  x9, x13,  x1);
        quarter(x10, x14,  x2,  x6);
        quarter(x15,  x3,  x7, x11);
        quarter( x0,  x1,  x2,  x3);
        quarter( x5,  x6,  x7,  x4);
        quarter(x10, x11,  x8,  x9);
        quarter(x15, x12, x13, x14);
    }

    X[0] += x0;   X[1] += x1;   X[2] += x2;   X[3] += x3;
    X[4] += x4;   X[5] += x5;   X[6] += x6;   X[7] += x7;
    X[8] += x8;   X[9] += x9;  X[10] += x10; X[11] += x11;
   X[12] += x12; X[13] += x13; X[14] += x14; X[15] += x15;

#undef quarter
}

/* ChaCha20, rounds must be a multiple of 2 */
static void neoscrypt_chacha(uint *X, uint rounds) {
    uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, t;

    x0 = X[0];   x1 = X[1];   x2 = X[2];   x3 = X[3];
    x4 = X[4];   x5 = X[5];   x6 = X[6];   x7 = X[7];
    x8 = X[8];   x9 = X[9];  x10 = X[10]; x11 = X[11];
   x12 = X[12]; x13 = X[13]; x14 = X[14]; x15 = X[15];

#define quarter(a,b,c,d) \
    a += b; t = d ^ a; d = ROTL32(t, 16); \
    c += d; t = b ^ c; b = ROTL32(t, 12); \
    a += b; t = d ^ a; d = ROTL32(t,  8); \
    c += d; t = b ^ c; b = ROTL32(t,  7);

    for(; rounds; rounds -= 2) {
        quarter( x0,  x4,  x8, x12);
        quarter( x1,  x5,  x9, x13);
        quarter( x2,  x6, x10, x14);
        quarter( x3,  x7, x11, x15);
        quarter( x0,  x5, x10, x15);
        quarter( x1,  x6, x11, x12);
        quarter( x2,  x7,  x8, x13);
        quarter( x3,  x4,  x9, x14);
    }

    X[0] += x0;   X[1] += x1;   X[2] += x2;   X[3] += x3;
    X[4] += x4;   X[5] += x5;   X[6] += x6;   X[7] += x7;
    X[8] += x8;   X[9] += x9;  X[10] += x10; X[11] += x11;
   X[12] += x12; X[13] += x13; X[14] += x14; X[15] += x15;

#undef quarter
}

/* Fast 32-bit / 64-bit memcpy();
 * len must be a multiple of 32 bytes */
static void neoscrypt_blkcpy(void *dstp, const void *srcp, uint len) {
    size_t *dst = (size_t *) dstp;
    size_t *src = (size_t *) srcp;
    uint i;

    for(i = 0; i < (len / sizeof(size_t)); i += 4) {
        dst[i]     = src[i];
        dst[i + 1] = src[i + 1];
        dst[i + 2] = src[i + 2];
        dst[i + 3] = src[i + 3];
    }
}

/* Fast 32-bit / 64-bit block swapper;
 * len must be a multiple of 32 bytes */
static void neoscrypt_blkswp(void *blkAp, void *blkBp, uint len) {
    size_t *blkA = (size_t *) blkAp;
    size_t *blkB = (size_t *) blkBp;
    register size_t t0, t1, t2, t3;
    uint i;

    for(i = 0; i < (len / sizeof(size_t)); i += 4) {
        t0          = blkA[i];
        t1          = blkA[i + 1];
        t2          = blkA[i + 2];
        t3          = blkA[i + 3];
        blkA[i]     = blkB[i];
        blkA[i + 1] = blkB[i + 1];
        blkA[i + 2] = blkB[i + 2];
        blkA[i + 3] = blkB[i + 3];
        blkB[i]     = t0;
        blkB[i + 1] = t1;
        blkB[i + 2] = t2;
        blkB[i + 3] = t3;
    }
}

/* Fast 32-bit / 64-bit block XOR engine;
 * len must be a multiple of 32 bytes */
static void neoscrypt_blkxor(void *dstp, const void *srcp, uint len) {
    size_t *dst = (size_t *) dstp;
    size_t *src = (size_t *) srcp;
    uint i;

    for(i = 0; i < (len / sizeof(size_t)); i += 4) {
        dst[i]     ^= src[i];
        dst[i + 1] ^= src[i + 1];
        dst[i + 2] ^= src[i + 2];
        dst[i + 3] ^= src[i + 3];
    }
}

/* 32-bit / 64-bit optimised memcpy() */
void neoscrypt_copy(void *dstp, const void *srcp, uint len) {
    size_t *dst = (size_t *) dstp;
    size_t *src = (size_t *) srcp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(size_t)); i++)
      dst[i] = src[i];

    tail = len & (sizeof(size_t) - 1);
    if(tail) {
        uchar *dstb = (uchar *) dstp;
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstb[i] = srcb[i];
    }
}

/* 32-bit / 64-bit optimised memory erase aka memset() to zero */
void neoscrypt_erase(void *dstp, uint len) {
    const size_t null = 0;
    size_t *dst = (size_t *) dstp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(size_t)); i++)
      dst[i] = null;

    tail = len & (sizeof(size_t) - 1);
    if(tail) {
        uchar *dstb = (uchar *) dstp;

        for(i = len - tail; i < len; i++)
          dstb[i] = (uchar)null;
    }
}

/* 32-bit / 64-bit optimised XOR engine */
void neoscrypt_xor(void *dstp, const void *srcp, uint len) {
    size_t *dst = (size_t *) dstp;
    size_t *src = (size_t *) srcp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(size_t)); i++)
      dst[i] ^= src[i];

    tail = len & (sizeof(size_t) - 1);
    if(tail) {
        uchar *dstb = (uchar *) dstp;
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstb[i] ^= srcb[i];
    }
}


/* BLAKE2s */

/* Parameter block of 32 bytes */
typedef struct blake2s_param_t {
    uchar digest_length;
    uchar key_length;
    uchar fanout;
    uchar depth;
    uint  leaf_length;
    uchar node_offset[6];
    uchar node_depth;
    uchar inner_length;
    uchar salt[8];
    uchar personal[8];
} blake2s_param;

/* State block of 256 bytes */
typedef struct blake2s_state_t {
    uint  h[8];
    uint  t[2];
    uint  f[2];
    uchar buf[2 * BLOCK_SIZE];
    uint  buflen;
    uint  padding[3];
    uchar tempbuf[BLOCK_SIZE];
} blake2s_state;

static const uint blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};


/* Buffer mixer (compressor) */
static void blake2s_compress(blake2s_state *S) {
    uint *v = (uint *) S->tempbuf;
    uint *m = (uint *) S->buf;
    register uint t0, t1, t2, t3;

    v[0]  = S->h[0];
    v[1]  = S->h[1];
    v[2]  = S->h[2];
    v[3]  = S->h[3];
    v[4]  = S->h[4];
    v[5]  = S->h[5];
    v[6]  = S->h[6];
    v[7]  = S->h[7];
    v[8]  = blake2s_IV[0];
    v[9]  = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = S->t[0] ^ blake2s_IV[4];
    v[13] = S->t[1] ^ blake2s_IV[5];
    v[14] = S->f[0] ^ blake2s_IV[6];
    v[15] = S->f[1] ^ blake2s_IV[7];

/* Round 0 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[0];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[1];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[2];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[3];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[4];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[5];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[6];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[7];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[8];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[9];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[10];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[11];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[12];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[13];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[14];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[15];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 1 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[14];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[10];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[4];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[8];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[9];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[15];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[13];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[6];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[1];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[12];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[0];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[2];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[11];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[7];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[5];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[3];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 2 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[11];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[8];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[12];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[0];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[5];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[2];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[15];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[13];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[10];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[14];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[3];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[6];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[7];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[1];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[9];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[4];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 3 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[7];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[9];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[3];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[1];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[13];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[12];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[11];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[14];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[2];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[6];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[5];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[10];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[4];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[0];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[15];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[8];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 4 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[9];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[0];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[5];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[7];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[2];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[4];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[10];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[15];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[14];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[1];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[11];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[12];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[6];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[8];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[3];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[13];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 5 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[2];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[12];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[6];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[10];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[0];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[11];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[8];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[3];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[4];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[13];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[7];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[5];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[15];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[14];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[1];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[9];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 6 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[12];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[5];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[1];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[15];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[14];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[13];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[4];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[10];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[0];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[7];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[6];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[3];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[9];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[2];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[8];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[11];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 7 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[13];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[11];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[7];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[14];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[12];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[1];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[3];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[9];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[5];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[0];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[15];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[4];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[8];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[6];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[2];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[10];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 8 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[6];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[15];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[14];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[9];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[11];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[3];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[0];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[8];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[12];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[2];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[13];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[7];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[1];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[4];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[10];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[5];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

/* Round 9 */
    t0 = v[0];
    t1 = v[4];
    t0 = t0 + t1 + m[10];
    t3 = v[12];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[2];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    t0 = v[1];
    t1 = v[5];
    t0 = t0 + t1 + m[8];
    t3 = v[13];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[4];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[2];
    t1 = v[6];
    t0 = t0 + t1 + m[7];
    t3 = v[14];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[6];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[3];
    t1 = v[7];
    t0 = t0 + t1 + m[1];
    t3 = v[15];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[5];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[0];
    t1 = v[5];
    t0 = t0 + t1 + m[15];
    t3 = v[15];
    t2 = v[10];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[11];
    v[0] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[15] = t3;
    t2 = t2 + t3;
    v[10] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[5] = t1;

    t0 = v[1];
    t1 = v[6];
    t0 = t0 + t1 + m[9];
    t3 = v[12];
    t2 = v[11];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[14];
    v[1] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[12] = t3;
    t2 = t2 + t3;
    v[11] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[6] = t1;

    t0 = v[2];
    t1 = v[7];
    t0 = t0 + t1 + m[3];
    t3 = v[13];
    t2 = v[8];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[12];
    v[2] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[13] = t3;
    t2 = t2 + t3;
    v[8] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[7] = t1;

    t0 = v[3];
    t1 = v[4];
    t0 = t0 + t1 + m[13];
    t3 = v[14];
    t2 = v[9];
    t3 = ROTR32(t3 ^ t0, 16);
    t2 = t2 + t3;
    t1 = ROTR32(t1 ^ t2, 12);
    t0 = t0 + t1 + m[0];
    v[3] = t0;
    t3 = ROTR32(t3 ^ t0, 8);
    v[14] = t3;
    t2 = t2 + t3;
    v[9] = t2;
    t1 = ROTR32(t1 ^ t2, 7);
    v[4] = t1;

    S->h[0] ^= v[0] ^ v[8];
    S->h[1] ^= v[1] ^ v[9];
    S->h[2] ^= v[2] ^ v[10];
    S->h[3] ^= v[3] ^ v[11];
    S->h[4] ^= v[4] ^ v[12];
    S->h[5] ^= v[5] ^ v[13];
    S->h[6] ^= v[6] ^ v[14];
    S->h[7] ^= v[7] ^ v[15];
}

static void blake2s_update(blake2s_state *S, const uchar *input,
  uint input_size) {
    uint left, fill;

    while(input_size > 0) {
        left = S->buflen;
        fill = 2 * BLOCK_SIZE - left;
        if(input_size > fill) {
            /* Buffer fill */
            neoscrypt_copy(S->buf + left, input, fill);
            S->buflen += fill;
            /* Counter increment */
            S->t[0] += BLOCK_SIZE;
            /* Compress */
            blake2s_compress(S);
            /* Shift buffer left */
            neoscrypt_copy(S->buf, S->buf + BLOCK_SIZE, BLOCK_SIZE);
            S->buflen -= BLOCK_SIZE;
            input += fill;
            input_size -= fill;
        } else {
            neoscrypt_copy(S->buf + left, input, input_size);
            S->buflen += input_size;
            /* Do not compress */
            input += input_size;
            input_size = 0;
        }
    }
}

void neoscrypt_blake2s(const void *input, const uint input_size,
  const void *key, const uchar key_size, void *output, const uchar output_size) {
    uchar block[BLOCK_SIZE];
    blake2s_param P[1];
    blake2s_state S[1];

    /* Initialise */
    neoscrypt_erase(P, 32);
    P->digest_length = output_size;
    P->key_length    = key_size;
    P->fanout        = 1;
    P->depth         = 1;

    neoscrypt_erase(S, 256);
    neoscrypt_copy(S, blake2s_IV, 32);
    neoscrypt_xor(S, P, 32);

    neoscrypt_erase(block, BLOCK_SIZE);
    neoscrypt_copy(block, key, key_size);
    blake2s_update(S, (uchar *) block, BLOCK_SIZE);

    /* Update */
    blake2s_update(S, (uchar *) input, input_size);

    /* Finish */
    if(S->buflen > BLOCK_SIZE) {
        S->t[0] += BLOCK_SIZE;
        blake2s_compress(S);
        S->buflen -= BLOCK_SIZE;
        neoscrypt_copy(S->buf, S->buf + BLOCK_SIZE, S->buflen);
    }
    S->t[0] += S->buflen;
    S->f[0] = ~0U;
    neoscrypt_erase(S->buf + S->buflen, 2 * BLOCK_SIZE - S->buflen);
    blake2s_compress(S);

    /* Write back */
    neoscrypt_copy(output, S, output_size);
}


/* Initialisation vector with a parameter block XOR'ed in */
static const uint blake2s_IV_P_XOR[8] = {
    0x6B08C647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/* Performance optimised FastKDF with BLAKE2s integrated */
void neoscrypt_fastkdf_opt(const uchar *password, const uchar *salt,
  uchar *output, uint mode) {
    const size_t stack_align = 0x40;
    uint bufptr, output_len, i, j;
    uchar *A, *B;
    uint *S;

    /* Align and set up the buffers in stack */
#ifdef _MSC_VER
    uchar *stack = (uchar *) malloc(864 + stack_align);
#else
    uchar stack[864 + stack_align];
#endif
    A = (uchar *) (((size_t)stack & ~(stack_align - 1)) + stack_align);
    B = &A[320];
    S = (uint *) &A[608];

    neoscrypt_copy(&A[0],   &password[0], 80);
    neoscrypt_copy(&A[80],  &password[0], 80);
    neoscrypt_copy(&A[160], &password[0], 80);
    neoscrypt_copy(&A[240], &password[0], 16);
    neoscrypt_copy(&A[256], &password[0], 64);

    if(!mode) {
        output_len = 256;
        neoscrypt_copy(&B[0],   &salt[0], 80);
        neoscrypt_copy(&B[80],  &salt[0], 80);
        neoscrypt_copy(&B[160], &salt[0], 80);
        neoscrypt_copy(&B[240], &salt[0], 16);
        neoscrypt_copy(&B[256], &salt[0], 32);
    } else {
        output_len = 32;
        neoscrypt_copy(&B[0],   &salt[0], 256);
        neoscrypt_copy(&B[256], &salt[0], 32);
    }

    for(i = 0, bufptr = 0; i < 32; i++) {

        /* BLAKE2s: initialise */
        neoscrypt_copy(&S[0], blake2s_IV_P_XOR, 32);
        neoscrypt_erase(&S[8], 16);

        /* BLAKE2s: update key */
        neoscrypt_copy(&S[12], &B[bufptr], 32);
        neoscrypt_erase(&S[20], 32);

        /* BLAKE2s: compress IV using key */
        S[8] = 64;
        blake2s_compress((blake2s_state *) S);

        /* BLAKE2s: update input */
        neoscrypt_copy(&S[12], &A[bufptr], 64);

        /* BLAKE2s: compress again using input */
        S[8] = 128;
        S[10] = ~0U;
        blake2s_compress((blake2s_state *) S);

        for(j = 0, bufptr = 0; j < 8; j++) {
          bufptr += S[j];
          bufptr += (S[j] >> 8);
          bufptr += (S[j] >> 16);
          bufptr += (S[j] >> 24);
        }
        bufptr &= 0xFF;

        neoscrypt_xor(&B[bufptr], &S[0], 32);

        if(bufptr < 32)
          neoscrypt_copy(&B[256 + bufptr], &B[bufptr], 32 - bufptr);
        else if(bufptr > 224)
          neoscrypt_copy(&B[0], &B[256], bufptr - 224);

    }

    i = 256 - bufptr;
    if(i >= output_len) {
        neoscrypt_xor(&B[bufptr], &A[0], output_len);
        neoscrypt_copy(&output[0], &B[bufptr], output_len);
    } else {
        neoscrypt_xor(&B[bufptr], &A[0], i);
        neoscrypt_xor(&B[0], &A[i], output_len - i);
        neoscrypt_copy(&output[0], &B[bufptr], i);
        neoscrypt_copy(&output[i], &B[0], output_len - i);
    }

#ifdef _MSC_VER
    free(stack);
#endif
}


/* Configurable optimised block mixer */
static void neoscrypt_blkmix(uint *X, uint *Y, uint r, uint mixmode) {
    uint i, mixer, rounds;

    mixer  = mixmode >> 8;
    rounds = mixmode & 0xFF;

    /* NeoScrypt flow:                   Scrypt flow:
         Xa ^= Xd;  M(Xa'); Ya = Xa";      Xa ^= Xb;  M(Xa'); Ya = Xa";
         Xb ^= Xa"; M(Xb'); Yb = Xb";      Xb ^= Xa"; M(Xb'); Yb = Xb";
         Xc ^= Xb"; M(Xc'); Yc = Xc";      Xa" = Ya;
         Xd ^= Xc"; M(Xd'); Yd = Xd";      Xb" = Yb;
         Xa" = Ya; Xb" = Yc;
         Xc" = Yb; Xd" = Yd; */

    if(r == 1) {
        if(mixer) {
            neoscrypt_blkxor(&X[0], &X[16], BLOCK_SIZE);
            neoscrypt_chacha(&X[0], rounds);
            neoscrypt_blkxor(&X[16], &X[0], BLOCK_SIZE);
            neoscrypt_chacha(&X[16], rounds);
        } else {
            neoscrypt_blkxor(&X[0], &X[16], BLOCK_SIZE);
            neoscrypt_salsa(&X[0], rounds);
            neoscrypt_blkxor(&X[16], &X[0], BLOCK_SIZE);
            neoscrypt_salsa(&X[16], rounds);
        }
        return;
    }

    if(r == 2) {
        if(mixer) {
            neoscrypt_blkxor(&X[0], &X[48], BLOCK_SIZE);
            neoscrypt_chacha(&X[0], rounds);
            neoscrypt_blkxor(&X[16], &X[0], BLOCK_SIZE);
            neoscrypt_chacha(&X[16], rounds);
            neoscrypt_blkxor(&X[32], &X[16], BLOCK_SIZE);
            neoscrypt_chacha(&X[32], rounds);
            neoscrypt_blkxor(&X[48], &X[32], BLOCK_SIZE);
            neoscrypt_chacha(&X[48], rounds);
            neoscrypt_blkswp(&X[16], &X[32], BLOCK_SIZE);
        } else {
            neoscrypt_blkxor(&X[0], &X[48], BLOCK_SIZE);
            neoscrypt_salsa(&X[0], rounds);
            neoscrypt_blkxor(&X[16], &X[0], BLOCK_SIZE);
            neoscrypt_salsa(&X[16], rounds);
            neoscrypt_blkxor(&X[32], &X[16], BLOCK_SIZE);
            neoscrypt_salsa(&X[32], rounds);
            neoscrypt_blkxor(&X[48], &X[32], BLOCK_SIZE);
            neoscrypt_salsa(&X[48], rounds);
            neoscrypt_blkswp(&X[16], &X[32], BLOCK_SIZE);
        }
        return;
    }

    /* Reference code for any reasonable r */
    for(i = 0; i < 2 * r; i++) {
        if(i) neoscrypt_blkxor(&X[16 * i], &X[16 * (i - 1)], BLOCK_SIZE);
        else  neoscrypt_blkxor(&X[0], &X[16 * (2 * r - 1)], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[16 * i], rounds);
        else
          neoscrypt_salsa(&X[16 * i], rounds);
        neoscrypt_blkcpy(&Y[16 * i], &X[16 * i], BLOCK_SIZE);
    }
    for(i = 0; i < r; i++)
      neoscrypt_blkcpy(&X[16 * i], &Y[16 * 2 * i], BLOCK_SIZE);
    for(i = 0; i < r; i++)
      neoscrypt_blkcpy(&X[16 * (i + r)], &Y[16 * (2 * i + 1)], BLOCK_SIZE);
}


/* NeoScrypt core engine:
 * p = 1, salt = password;
 * Basic customisation (required):
 *   profile bit 0:
 *     0 = NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20;
 *     1 = Scrypt(1024, 1, 1) with Salsa20/8;
 *   profile bits 4 to 1:
 *     0000 = FastKDF-BLAKE2s;
 *     0001 = PBKDF2-HMAC-SHA256;
 *     0010 = PBKDF2-HMAC-BLAKE256;
 * Extended customisation (optional):
 *   profile bit 31:
 *     0 = extended customisation absent;
 *     1 = extended customisation present;
 *   profile bits 7 to 5 (rfactor):
 *     000 = r of 1;
 *     001 = r of 2;
 *     010 = r of 4;
 *     ...
 *     111 = r of 128;
 *   profile bits 12 to 8 (Nfactor):
 *     00000 = N of 2;
 *     00001 = N of 4;
 *     00010 = N of 8;
 *     .....
 *     00110 = N of 128;
 *     .....
 *     01001 = N of 1024;
 *     .....
 *     11110 = N of 2147483648;
 *   profile bits 30 to 13 are reserved */
void neoscrypt(const uchar *password, uchar *output) {
    const size_t stack_align = 0x40;
    uint N = 128, r = 2, dblmix = 1, mixmode = 0x14;
    uint i, j;
    uint *X, *Y, *Z, *V;
    
#ifdef _MSC_VER
    uchar *stack = (uchar *) malloc((N + 3) * r * 2 * BLOCK_SIZE + stack_align);
#else
    uchar stack[(N + 3) * r * 2 * BLOCK_SIZE + stack_align];
#endif
    /* X = r * 2 * BLOCK_SIZE */
    X = (uint *) (((size_t)stack & ~(stack_align - 1)) + stack_align);
    /* Z is a copy of X for ChaCha */
    Z = &X[32 * r];
    /* Y is an X sized temporal space */
    Y = &X[64 * r];
    /* V = N * r * 2 * BLOCK_SIZE */
    V = &X[96 * r];

    /* X = KDF(password, salt) */
    neoscrypt_fastkdf_opt(password, password, (uchar *) X, 0);

    /* Process ChaCha 1st, Salsa 2nd and XOR them into FastKDF; otherwise Salsa only */

    if(dblmix) {
        /* blkcpy(Z, X) */
        neoscrypt_blkcpy(&Z[0], &X[0], r * 2 * BLOCK_SIZE);

        /* Z = SMix(Z) */
        for(i = 0; i < N; i++) {
            /* blkcpy(V, Z) */
            neoscrypt_blkcpy(&V[i * (32 * r)], &Z[0], r * 2 * BLOCK_SIZE);
            /* blkmix(Z, Y) */
            neoscrypt_blkmix(&Z[0], &Y[0], r, (mixmode | 0x0100));
        }

        for(i = 0; i < N; i++) {
            /* integerify(Z) mod N */
            j = (32 * r) * (Z[16 * (2 * r - 1)] & (N - 1));
            /* blkxor(Z, V) */
            neoscrypt_blkxor(&Z[0], &V[j], r * 2 * BLOCK_SIZE);
            /* blkmix(Z, Y) */
            neoscrypt_blkmix(&Z[0], &Y[0], r, (mixmode | 0x0100));
        }
    }

    /* X = SMix(X) */
    for(i = 0; i < N; i++) {
        /* blkcpy(V, X) */
        neoscrypt_blkcpy(&V[i * (32 * r)], &X[0], r * 2 * BLOCK_SIZE);
        /* blkmix(X, Y) */
        neoscrypt_blkmix(&X[0], &Y[0], r, mixmode);
    }
    for(i = 0; i < N; i++) {
        /* integerify(X) mod N */
        j = (32 * r) * (X[16 * (2 * r - 1)] & (N - 1));
        /* blkxor(X, V) */
        neoscrypt_blkxor(&X[0], &V[j], r * 2 * BLOCK_SIZE);
        /* blkmix(X, Y) */
        neoscrypt_blkmix(&X[0], &Y[0], r, mixmode);
    }

    if(dblmix)
      /* blkxor(X, Z) */
      neoscrypt_blkxor(&X[0], &Z[0], r * 2 * BLOCK_SIZE);

    /* output = KDF(password, X) */
    neoscrypt_fastkdf_opt(password, (uchar *) X, output, 1);

#ifdef _MSC_VER
    free(stack);
#endif
}
