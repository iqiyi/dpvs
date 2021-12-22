
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#include "conhash.h"
#include "conhash_inter.h"


void conhash_md5_digest(const u_char *instr, u_char digest[16])
{
    md5_state_t md5state;

    md5_init(&md5state);
    md5_append(&md5state, instr, strlen((const char*)instr));
    md5_finish(&md5state, digest);
}

static void __get_vnodes(util_rbtree_node_t *node, void *data)
{
    struct __get_vnodes_s *vnodes = (struct __get_vnodes_s *)data;
    if(vnodes->cur < vnodes->size)
    {
        vnodes->values[vnodes->cur++] = node->key;
    }
}
void conhash_get_vnodes(const struct conhash_s *conhash, long *values, int size)
{
    struct __get_vnodes_s vnodes;
    if((conhash==NULL) || (values==NULL) || (size<=0))
    {
        return;
    }
    vnodes.values = values;
    vnodes.size = size;
    vnodes.cur = 0;
    util_rbtree_mid_travel((util_rbtree_t *)&(conhash->vnode_tree), __get_vnodes, &vnodes);
}

u_int conhash_get_vnodes_num(const struct conhash_s *conhash)
{
    if(conhash == NULL)
    {
        return 0;
    }
    return conhash->ivnodes;
}
