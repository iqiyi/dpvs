
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#include "conhash.h"
#include "conhash_inter.h"

struct conhash_s* conhash_init(conhash_cb_hashfunc pfhash)
{
    /* alloc memory and set to zero */
    struct conhash_s *conhash = (struct conhash_s*)rte_zmalloc("conhash",sizeof(struct conhash_s), RTE_CACHE_LINE_SIZE);
    if(conhash == NULL)
    {
        return NULL;
    }
    do
        {
        /* setup callback functions */
        if(pfhash != NULL)
        {
            conhash->cb_hashfunc = (long (*)(const char *))pfhash;
        }
        else
        {
            conhash->cb_hashfunc = (long (*)(const char *))__conhash_hash_def;
        }
        util_rbtree_init(&conhash->vnode_tree);
        return conhash;

        }while(0);

    rte_free(conhash);
    return NULL;
}

void conhash_fini(struct conhash_s *conhash,void (*node_fini)(struct node_s*))
{
    if(conhash != NULL)
    {
         /* free rb tree */
        while(!util_rbtree_isempty(&(conhash->vnode_tree)))
        {
            struct node_s *node;
            util_rbtree_node_t *rbnode = conhash->vnode_tree.root;
            util_rbtree_delete(&(conhash->vnode_tree), rbnode);
            if (rbnode && rbnode->data)
            {
                node = ((struct virtual_node_s*)rbnode->data)->node;
                if (--(node->replicas) == 0)
                    (*node_fini)(node);
            }
            __conhash_del_rbnode(rbnode);
        }
        rte_free(conhash);
    }
}

void conhash_set_node(struct node_s *node, const char *iden, u_int replica)
{
    strncpy(node->iden, iden, sizeof(node->iden)-1);
    node->replicas = replica;
    node->flag = NODE_FLAG_INIT;
}

int conhash_add_node(struct conhash_s *conhash, struct node_s *node)
{
    if((conhash==NULL) || (node==NULL))
    {
        return -1;
    }
    /* check node fisrt */
    if(!(node->flag&NODE_FLAG_INIT) || (node->flag&NODE_FLAG_IN))
    {
        return -1;
    }
    node->flag |= NODE_FLAG_IN;
    /* add replicas of server */
    __conhash_add_replicas(conhash, node);

    return 0;
}

int conhash_del_node(struct conhash_s *conhash, struct node_s *node)
{
   if((conhash==NULL) || (node==NULL))
    {
        return -1;
    }
    /* check node first */
    if(!(node->flag&NODE_FLAG_INIT) || !(node->flag&NODE_FLAG_IN))
    {
        return -1;
    }
    node->flag &= (~NODE_FLAG_IN);
    /* add replicas of server */
    __conhash_del_replicas(conhash, node);

    return 0;
}

const struct node_s* conhash_lookup(const struct conhash_s *conhash, const char *object)
{
    long hash;
    const util_rbtree_node_t *rbnode;
    if((conhash==NULL) || (conhash->ivnodes==0) || (object==NULL))
    {
        return NULL;
    }
    /* calc hash value */
    hash = conhash->cb_hashfunc(object);

    rbnode = util_rbtree_lookup((util_rbtree_t *)&(conhash->vnode_tree), hash);
    if(rbnode != NULL)
    {
        struct virtual_node_s *vnode = rbnode->data;
        return vnode->node;
    }
    return NULL;
}
