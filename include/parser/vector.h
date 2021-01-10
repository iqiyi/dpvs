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
#ifndef __VECTOR_H__
#define __VECTOR_H__

#include <assert.h>
#include "parser/utils.h"

struct vector {
    uint32_t allocated;
    void **slot;
};
typedef struct vector* vector_t;

#define VECTOR_SLOT(V, E) ((V)->slot[(E)])
#define VECTOR_SIZE(V) ((V)->allocated)

#define vector_foreach_slot(v, p, i) \
    for (i = 0; i < (v)->allocated && ((p) = (v)->slot[i]; i++))

static inline vector_t vector_alloc(void)
{
    return (vector_t) MALLOC(sizeof(struct vector));
}

static inline void vector_alloc_slot(vector_t v)
{
    assert(v);

    v->allocated += 1;
    if (v->slot)
        v->slot = REALLOC(v->slot, sizeof(void *) * v->allocated);
    else
        v->slot = MALLOC(sizeof(void *) * v->allocated);
}

static inline void vector_set_slot(vector_t v, void *value)
{
    assert(v);

    v->slot[v->allocated - 1] = value;
}

static inline void vector_insert_slot(vector_t v, uint32_t slot, void *value)
{
    assert(v && value);
    uint32_t i;

    for (i = v->allocated - 2; i >= slot; i--)
        v->slot[i + 1] = v->slot[i];

    v->slot[slot] = value;
}

static inline void vector_free(vector_t v)
{
    assert(v);

    FREE(v->slot);
    FREE(v);
}

static inline void vector_str_free(vector_t v)
{
    assert(v);
    uint32_t i;
    char *str;

    for (i = 0; i < VECTOR_SIZE(v); i++)
        if ((str = VECTOR_SLOT(v, i)) != NULL)
            FREE(str);

    vector_free(v);
}

#ifdef DPVS_CFG_PARSER_DEBUG
static inline void vector_dump(vector_t v)
{
    assert(v);
    uint32_t i;

    printf("vector size: %u\n", v->allocated);

    for (i = 0; i < v->allocated; i++)
        if (v->slot[i] != NULL)
            printf("  [%u]: %p", i, VECTOR_SLOT(v,i));
    printf("\n");

    fflush(stdout);
}

static inline void vector_str_dump(vector_t v)
{
    assert(v);
    uint32_t i;
    char *str;

    printf("vector string:\n");

    for (i = 0; i < VECTOR_SIZE(v); i++) {
        str = VECTOR_SLOT(v, i);
        printf("  [%u]=%s", i, str);
    }
    printf("\n");

    fflush(stdout);
}
#endif

#endif
