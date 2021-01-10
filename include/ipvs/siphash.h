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
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 *
 * see include/linux/siphash.h for more details.
 *
 */

#ifndef _SIPHASH_H
#define _SIPHASH_H

#include <stdint.h>
#include <stddef.h>
#include <linux/types.h>
#include <rte_byteorder.h>

typedef struct {
    unsigned long key[2];
} hsiphash_key_t;

uint32_t __hsiphash_aligned(const void *data, size_t len,
        const hsiphash_key_t *key);

uint32_t hsiphash_1u32(const uint32_t a, const hsiphash_key_t *key);
uint32_t hsiphash_2u32(const uint32_t a, const uint32_t b,
        const hsiphash_key_t *key);
uint32_t hsiphash_3u32(const uint32_t a, const uint32_t b, const uint32_t c,
        const hsiphash_key_t *key);
uint32_t hsiphash_4u32(const uint32_t a, const uint32_t b, const uint32_t c,
        const uint32_t d, const hsiphash_key_t *key);

static inline uint32_t ___hsiphash_aligned(const __le32 *data, size_t len,
        const hsiphash_key_t *key)
{
    if (__builtin_constant_p(len) && len == 4)
        return hsiphash_1u32(rte_le_to_cpu_32(data[0]), key);
    if (__builtin_constant_p(len) && len == 8)
        return hsiphash_2u32(rte_le_to_cpu_32(data[0]),
                rte_le_to_cpu_32(data[1]), key);
    if (__builtin_constant_p(len) && len == 12)
        return hsiphash_3u32(rte_le_to_cpu_32(data[0]),
                rte_le_to_cpu_32(data[1]), rte_le_to_cpu_32(data[2]), key);
    if (__builtin_constant_p(len) && len == 16)
        return hsiphash_4u32(rte_le_to_cpu_32(data[0]),
                rte_le_to_cpu_32(data[1]), rte_le_to_cpu_32(data[2]),
                rte_le_to_cpu_32(data[3]), key);
    return __hsiphash_aligned(data, len, key);
}

/**
 * hsiphash - compute 32-bit hsiphash PRF value
 * @data: buffer to hash
 * @size: size of @data
 * @key: the hsiphash key
 */
static inline uint32_t hsiphash(const void *data, size_t len,
        const hsiphash_key_t *key)
{
    return ___hsiphash_aligned(data, len, key);
}

#endif /* _SIPHASH_H */

