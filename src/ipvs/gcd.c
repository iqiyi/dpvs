/*
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
 * see lib/math/gcd.c for more details.
 *
 * yangxingwu <xingwu.yang@gmail.com>, Feb 2019, initial.
 *
 */

#include "ipvs/kcompat.h"
#include "ipvs/gcd.h"

/*
 * This implements the binary GCD algorithm. (Often attributed to Stein,
 * but as Knuth has noted, appears in a first-century Chinese math text.)
 *
 * This is faster than the division-based algorithm even on x86, which
 * has decent hardware division.
 */

/**
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
