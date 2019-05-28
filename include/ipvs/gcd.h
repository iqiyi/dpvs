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
 * see include/linux/gcd.h for more details.
 *
 * yangxingwu <xingwu.yang@gmail.com>, Feb 2019, initial.
 *
 */

#ifndef __GCD_H__
#define __GCD_H__

unsigned long gcd(unsigned long a, unsigned long b) __attribute__((const));

#endif /* __GCD_H__ */
