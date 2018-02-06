
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#ifndef __CONHASH_INTER_H_
#define __CONHASH_INTER_H_

#include "configure.h"
#include "md5.h"
#include "util_rbtree.h"


/* virtual node structure */
struct virtual_node_s
{
    unsigned long hash;
    struct node_s *node; /* pointer to node */
};

/* consistent hashing */
struct conhash_s
{
    util_rbtree_t vnode_tree; /* rbtree of virtual nodes */
    u_int ivnodes; /* virtual node number */
    long (*cb_hashfunc)(const char *);
};

struct __get_vnodes_s
{
    long *values;
    long size, cur;
};


int __conhash_vnode_cmp(const void *v1, const void *v2);

void __conhash_node2string(const struct node_s *node, u_int replica_idx, char buf[128], u_int *len);
unsigned long __conhash_hash_def(const char *instr);
void __conhash_add_replicas(struct conhash_s *conhash, struct node_s *node);
void __conhash_del_replicas(struct conhash_s *conhash, struct node_s *node);

util_rbtree_node_t *__conhash_get_rbnode(struct node_s *node, long hash);
void __conhash_del_rbnode(util_rbtree_node_t *rbnode);

#endif /* end __CONHASH_INTER_H_ */
