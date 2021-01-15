/*
 * DPVS is a software load balancer (Virtual Server) based on DPDK.
 *
 * Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 *
 * see lib/siphash.c for more details.
 */

#include "ipvs/siphash.h"

#define SIPROUND \
    do { \
        v0 += v1; v1 = rol64(v1, 13); v1 ^= v0; v0 = rol64(v0, 32); \
        v2 += v3; v3 = rol64(v3, 16); v3 ^= v2; \
        v0 += v3; v3 = rol64(v3, 21); v3 ^= v0; \
        v2 += v1; v1 = rol64(v1, 17); v1 ^= v2; v2 = rol64(v2, 32); \
    } while (0)

#define PREAMBLE(len) \
    uint64_t v0 = 0x736f6d6570736575ULL; \
    uint64_t v1 = 0x646f72616e646f6dULL; \
    uint64_t v2 = 0x6c7967656e657261ULL; \
    uint64_t v3 = 0x7465646279746573ULL; \
    uint64_t b = ((uint64_t)(len)) << 56; \
    v3 ^= key->key[1]; \
    v2 ^= key->key[0]; \
    v1 ^= key->key[1]; \
    v0 ^= key->key[0];

#if __BITS_PER_LONG == 64

/**
 * taken from definition in include/linux/bitops.h
 *
 * rol64 - rotate a 64-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline uint64_t rol64(uint64_t word, unsigned int shift)
{
    return (word << (shift & 63)) | (word >> ((-shift) & 63));
}

/* Note that on 64-bit, we make HalfSipHash1-3 actually be SipHash1-3, for
 * performance reasons. On 32-bit, below, we actually implement HalfSipHash1-3.
 */

#define HSIPROUND SIPROUND
#define HPREAMBLE(len) PREAMBLE(len)
#define HPOSTAMBLE \
	v3 ^= b; \
	HSIPROUND; \
	v0 ^= b; \
	v2 ^= 0xff; \
	HSIPROUND; \
	HSIPROUND; \
	HSIPROUND; \
	return (v0 ^ v1) ^ (v2 ^ v3);

uint32_t __hsiphash_aligned(const void *data, size_t len,
        const hsiphash_key_t *key)
{
    const uint8_t *end = data + len - (len % sizeof(uint64_t));
    const uint8_t left = len & (sizeof(uint64_t) - 1);
    uint64_t m;
    HPREAMBLE(len)
    for (; data != end; data += sizeof(uint64_t)) {
        m = rte_le_to_cpu_64(*((uint64_t *)data));
        v3 ^= m;
        HSIPROUND;
        v0 ^= m;
    }
    switch (left) {
    case 7: b |= ((uint64_t)end[6]) << 48; /* fall through */
    case 6: b |= ((uint64_t)end[5]) << 40; /* fall through */
    case 5: b |= ((uint64_t)end[4]) << 32; /* fall through */
    case 4: b |= rte_le_to_cpu_32(*((uint32_t *)data)); break;
    case 3: b |= ((uint64_t)end[2]) << 16; /* fall through */
    case 2: b |= rte_le_to_cpu_16(*((uint32_t *)data)); break;
    case 1: b |= end[0];
    }
    HPOSTAMBLE
}

/**
 * hsiphash_1u32 - compute 64-bit hsiphash PRF value of a uint32_t
 * @first: first uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_1u32(const uint32_t first, const hsiphash_key_t *key)
{
    HPREAMBLE(4)
    b |= first;
    HPOSTAMBLE
}

/**
 * hsiphash_2u32 - compute 32-bit hsiphash PRF value of 2 uint32_t
 * @first: first uint32_t
 * @second: second uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_2u32(const uint32_t first, const uint32_t second,
        const hsiphash_key_t *key)
{
    uint64_t combined = (uint64_t)second << 32 | first;
    HPREAMBLE(8)
    v3 ^= combined;
    HSIPROUND;
    v0 ^= combined;
    HPOSTAMBLE
}

/**
 * hsiphash_3u32 - compute 32-bit hsiphash PRF value of 3 uint32_t
 * @first: first uint32_t
 * @second: second uint32_t
 * @third: third uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_3u32(const uint32_t first, const uint32_t second,
        const uint32_t third, const hsiphash_key_t *key)
{
    uint64_t combined = (uint64_t)second << 32 | first;
    HPREAMBLE(12)
    v3 ^= combined;
    HSIPROUND;
    v0 ^= combined;
    b |= third;
    HPOSTAMBLE
}

/**
 * hsiphash_4u32 - compute 32-bit hsiphash PRF value of 4 uint32_t
 * @first: first uint32_t
 * @second: second uint32_t
 * @third: third uint32_t
 * @forth: forth uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_4u32(const uint32_t first, const uint32_t second,
        const uint32_t third, const uint32_t forth, const hsiphash_key_t *key)
{
    uint64_t combined = (uint64_t)second << 32 | first;
    HPREAMBLE(16)
    v3 ^= combined;
    HSIPROUND;
    v0 ^= combined;
    combined = (uint64_t)forth << 32 | third;
    v3 ^= combined;
    HSIPROUND;
    v0 ^= combined;
    HPOSTAMBLE
}

#else // __BITS_PER_LONG == 64

/**
 * taken from definition in include/linux/bitops.h
 *
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define HSIPROUND \
    do { \
        v0 += v1; v1 = rol32(v1, 5); v1 ^= v0; v0 = rol32(v0, 16); \
        v2 += v3; v3 = rol32(v3, 8); v3 ^= v2; \
        v0 += v3; v3 = rol32(v3, 7); v3 ^= v0; \
        v2 += v1; v1 = rol32(v1, 13); v1 ^= v2; v2 = rol32(v2, 16); \
    } while (0)

#define HPREAMBLE(len) \
    uint32_t v0 = 0; \
    uint32_t v1 = 0; \
    uint32_t v2 = 0x6c796765U; \
    uint32_t v3 = 0x74656462U; \
    uint32_t b = ((uint32_t)(len)) << 24; \
    v3 ^= key->key[1]; \
    v2 ^= key->key[0]; \
    v1 ^= key->key[1]; \
    v0 ^= key->key[0];

#define HPOSTAMBLE \
    v3 ^= b; \
    HSIPROUND; \
    v0 ^= b; \
    v2 ^= 0xff; \
    HSIPROUND; \
    HSIPROUND; \
    HSIPROUND; \
    return v1 ^ v3;

uint32_t __hsiphash_aligned(const void *data, size_t len, const hsiphash_key_t *key)
{
    const uint8_t *end = data + len - (len % sizeof(uint32_t));
    const uint8_t left = len & (sizeof(uint32_t) - 1);
    uint32_t m;
    HPREAMBLE(len)
    for (; data != end; data += sizeof(uint32_t)) {
        m = rte_le_to_cpu_32(*((uint32_t *)data));
        v3 ^= m;
        HSIPROUND;
        v0 ^= m;
    }
    switch (left) {
    case 3: b |= ((uint32_t)end[2]) << 16; /* fall through */
    case 2: b |= rte_le_to_cpu_16(*((uint16_t *)data)); break;
    case 1: b |= end[0];
    }
    HPOSTAMBLE
}

/**
 * hsiphash_1u32 - compute 32-bit hsiphash PRF value of a uint32_t
 * @first: first uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_1u32(const uint32_t first, const hsiphash_key_t *key)
{
    HPREAMBLE(4)
    v3 ^= first;
    HSIPROUND;
    v0 ^= first;
    HPOSTAMBLE
}

/**
 * hsiphash_2u32 - compute 32-bit hsiphash PRF value of 2 uint32_t
 * @first: first uint32_t
 * @second: second uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_2u32(const uint32_t first, const uint32_t second, const hsiphash_key_t *key)
{
    HPREAMBLE(8)
    v3 ^= first;
    HSIPROUND;
    v0 ^= first;
    v3 ^= second;
    HSIPROUND;
    v0 ^= second;
    HPOSTAMBLE
}

/**
 * hsiphash_3u32 - compute 32-bit hsiphash PRF value of 3 uint32_t
 * @first: first uint32_t
 * @second: second uint32_t
 * @third: third uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_3u32(const uint32_t first, const uint32_t second, const uint32_t third,
        const hsiphash_key_t *key)
{
    HPREAMBLE(12)
    v3 ^= first;
    HSIPROUND;
    v0 ^= first;
    v3 ^= second;
    HSIPROUND;
    v0 ^= second;
    v3 ^= third;
    HSIPROUND;
    v0 ^= third;
    HPOSTAMBLE
}

/**
 * hsiphash_4u32 - compute 32-bit hsiphash PRF value of 4 uint32_t
 * @first: first uint32_t
 * @second: second uint32_t
 * @third: third uint32_t
 * @forth: forth uint32_t
 * @key: the hsiphash key
 */
uint32_t hsiphash_4u32(const uint32_t first, const uint32_t second, const uint32_t third,
        const uint32_t forth, const hsiphash_key_t *key)
{
    HPREAMBLE(16)
    v3 ^= first;
    HSIPROUND;
    v0 ^= first;
    v3 ^= second;
    HSIPROUND;
    v0 ^= second;
    v3 ^= third;
    HSIPROUND;
    v0 ^= third;
    v3 ^= forth;
    HSIPROUND;
    v0 ^= forth;
    HPOSTAMBLE
}

#endif // __BITS_PER_LONG == 64

