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
 */

#include "ipvs/kcompat.h"

// taken from definition in include/asm-generic/bitops/builtin-__ffs.h
inline unsigned long __ffs(unsigned long word)
{
    return __builtin_ctzl(word);
}

// taken from definition in include/asm-generic/bitops/builtin-fls.h
inline int fls(unsigned int x)
{
    return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

/**
 * taken from definition in lib/math/gcd.c
 *
 * gcd - calculate and return the greatest common divisor of 2 unsigned longs
 * @a: first value
 * @b: second value
 */
unsigned long gcd(unsigned long a, unsigned long b)
{
    unsigned long r = a | b;

    if (!a || !b)
        return r;

    b >>= __ffs(b);
    if (b == 1)
        return r & -r;

    for (;;) {
        a >>= __ffs(a);
        if (a == 1)
            return r & -r;
        if (a == b)
            return a << __ffs(r);

        if (a < b)
            swap(a, b);
        a -= b;
    }
}


