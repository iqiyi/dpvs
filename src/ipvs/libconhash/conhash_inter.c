
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#include "conhash_inter.h"
#include "conhash.h"

/*
 * the default hash function, using md5 algorithm
 * @instr: input string
 */
unsigned long __conhash_hash_def(const char *instr)
{
    int i;
    long hash = 0;
    unsigned char digest[16];
    unsigned long a = 0;

    conhash_md5_digest((const u_char*)instr, digest);

    /* use successive 4-bytes from hash as numbers */
    for(i = 0; i < 4; i++)
    {
        hash += ((long)(digest[i*4 + 3]&0xFF) << 24)
            | ((long)(digest[i*4 + 2]&0xFF) << 16)
            | ((long)(digest[i*4 + 1]&0xFF) <<  8)
            | ((long)(digest[i*4 + 0]&0xFF));
    }

    a = hash;
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);

    /* ensure values are better spread all around the tree by multiplying
     * by a large prime close to 3/4 of the tree.
     */
    a =  a * 3221225473U;

    return a;
}

void __conhash_node2string(const struct node_s *node, u_int replica_idx, char buf[128], u_int *len)
{
#if (defined (WIN32) || defined (__WIN32))
    _snprintf_s(buf, 127, _TRUNCATE, "%s-%03d", node->iden, replica_idx);
#else
    snprintf(buf, 127, "%s-%03d", node->iden, replica_idx);
#endif
}

void __conhash_add_replicas(struct conhash_s *conhash, struct node_s *node)
{
    u_int i, len;
    long hash;
    char buff[128];
    util_rbtree_node_t *rbnode;
    for(i = 0; i < node->replicas; i++)
    {
        /* calc hash value of all virtual nodes */
        __conhash_node2string(node, i, buff, &len);
        hash = conhash->cb_hashfunc(buff);
        /* add virtual node, check duplication */
        if(util_rbtree_search(&(conhash->vnode_tree), hash) == NULL)
        {
            rbnode = __conhash_get_rbnode(node, hash);
            if(rbnode != NULL)
            {
                util_rbtree_insert(&(conhash->vnode_tree), rbnode);
                conhash->ivnodes++;
            }
        }
    }
}

void __conhash_del_replicas(struct conhash_s *conhash, struct node_s *node)
{
    u_int i, len;
    long hash;
    char buff[128];
    struct virtual_node_s *vnode;
    util_rbtree_node_t *rbnode;
    for(i = 0; i < node->replicas; i++)
    {
        /* calc hash value of all virtual nodes */
        __conhash_node2string(node, i, buff, &len);
        hash = conhash->cb_hashfunc(buff);
        rbnode = util_rbtree_search(&(conhash->vnode_tree), hash);
        if(rbnode != NULL)
        {
            vnode = rbnode->data;
            if((vnode->hash == hash) && (vnode->node == node))
            {
                conhash->ivnodes--;
                util_rbtree_delete(&(conhash->vnode_tree), rbnode);
                __conhash_del_rbnode(rbnode);
            }
        }
    }
}

util_rbtree_node_t *__conhash_get_rbnode(struct node_s *node, long hash)
{
    util_rbtree_node_t *rbnode;
    rbnode = (util_rbtree_node_t *)rte_zmalloc("rbnode", sizeof(util_rbtree_node_t), RTE_CACHE_LINE_SIZE);
    if(rbnode != NULL)
    {
        rbnode->key = hash;
        rbnode->data = rte_zmalloc("rbnode_data", sizeof(struct virtual_node_s), RTE_CACHE_LINE_SIZE);
        if(rbnode->data != NULL)
        {
            struct virtual_node_s *vnode = rbnode->data;
            vnode->hash = hash;
            vnode->node = node;
        }
        else
        {
            rte_free(rbnode);
            rbnode = NULL;
        }
    }
    return rbnode;
}

void __conhash_del_rbnode(util_rbtree_node_t *rbnode)
{
    struct virtual_node_s *node;
    node = rbnode->data;
    rte_free(node);
    rte_free(rbnode);
}
