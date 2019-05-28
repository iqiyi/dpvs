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
 * yangxingwu <xingwu.yang@gmail.com>, Feb 2019, initial.
 *
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
