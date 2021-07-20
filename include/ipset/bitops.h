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
 */
#ifndef __DPVS_IPSET_BITOPS_H__
#define __DPVS_IPSET_BITOPS_H__

#include <limits.h>
#include <string.h>
#include <stdbool.h>

/* Defines */
#define BIT_PER_LONG     (CHAR_BIT * sizeof(unsigned long))
#define BIT_MASK(idx)    (1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)    ((idx) / BIT_PER_LONG)

#define DIV_ROUND_UP(x,y)   (((x) + (y) - 1) / (y))
#define BITS_TO_LONGS(n)    DIV_ROUND_UP(n, BIT_PER_LONG)

/* Helpers */
static inline void set_bit(unsigned idx, unsigned long *bmap)
{
    bmap[BIT_WORD(idx)] |= BIT_MASK(idx);
}

static inline void clear_bit(unsigned idx, unsigned long *bmap)
{
    bmap[BIT_WORD(idx)] &= ~BIT_MASK(idx);
}

static inline bool test_bit(unsigned idx, const unsigned long *bmap)
{
    return !!(bmap[BIT_WORD(idx)] & BIT_MASK(idx));
}

static inline bool test_and_set_bit(unsigned idx, unsigned long *bmap)
{
    if (test_bit(idx, bmap))
        return true;

    set_bit(idx, bmap);

    return false;
}

static inline bool test_and_clear_bit(unsigned idx, unsigned long *bmap)
{
    if (test_bit(idx, bmap)) {
        clear_bit(idx, bmap);
        return true;
    }

    return false;
}

static inline void bitmap_zero(unsigned long *dst, unsigned int nbits)
{
    unsigned int len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
    memset(dst, 0, len);
}

#endif
