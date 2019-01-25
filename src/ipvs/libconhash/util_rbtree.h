
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#ifndef __UTIL_RLTREE_H_
#define __UTIL_RLTREE_H_

#include "configure.h"
#include <stdlib.h>

typedef struct util_rbtree_s util_rbtree_t;
typedef struct util_rbtree_node_s util_rbtree_node_t;

struct util_rbtree_node_s
{
    long key;
    util_rbtree_node_t *parent;
    util_rbtree_node_t *right;
    util_rbtree_node_t *left;
    int color;
    void *data;
};

struct util_rbtree_s
{
    util_rbtree_node_t *root;
    util_rbtree_node_t  null;
    u_int size;
};


#define util_rbt_black(rbnode)   ((rbnode)->color = 1)
#define util_rbt_red(rbnode)     ((rbnode)->color = 0)
#define util_rbt_isblack(rbnode) ((rbnode)->color == 1)
#define util_rbt_isred(rbnode)   ((rbnode)->color == 0)

/* clear a node's link */
#define rbt_clear_node(node) do{ \
    node->left = NULL;  \
    node->right = NULL; \
    node->parent = NULL; \
    }while(0)

/* is the tree empty */
#define util_rbtree_isempty(rbtree) ((rbtree)->root == &(rbtree)->null)

/*
 * find the min node of tree
 * return NULL is tree is empty
 */
#define util_rbtree_min(rbtree) util_rbsubtree_min((rbtree)->root, &(rbtree)->null)

/*
 * find the max node of tree
 * return NULL is tree is empty
 */
#define util_rbtree_max(rbtree) util_rbsubtree_max((rbtree)->root, &(rbtree)->null)

void util_rbtree_init(util_rbtree_t *rbtree);
void util_rbtree_insert(util_rbtree_t *rbtree, util_rbtree_node_t *node);
void util_rbtree_delete(util_rbtree_t *rbtree, util_rbtree_node_t *node);

/*
 * search node with key = @key in the tree
 * if no such node exist, return NULL
 */
util_rbtree_node_t* util_rbtree_search(util_rbtree_t *rbtree, long key);

/*
 * look node in the tree
 * return the first node with key >= @key;
 * if @key > all the key values in the tree, return the node with minimum key
 * return NULL if tree is empty
 */
util_rbtree_node_t* util_rbtree_lookup(util_rbtree_t *rbtree, long key);

/*
 * find the min node of subtree
 * @rbnode: root of the subtree
 * @sentinel : the sentinel node
 * return NULL if subtree is empty
 */
util_rbtree_node_t* util_rbsubtree_min(util_rbtree_node_t *node, util_rbtree_node_t *sentinel);

/*
 * find the max node of subtree
 * @rbnode: root of the subtree
 * @sentinel : the sentinel node
 * return NULL if subtree is empty
 */
util_rbtree_node_t* util_rbsubtree_max(util_rbtree_node_t *node, util_rbtree_node_t *sentinel);

/*
 * check whether a tree is a rb tree, the null node is n't checked
 * return 0: yes
 * return 1: root isn't black
 * return 2: node is in other color than black and red
 * return 3: tree's black height isn't unique
 * return 4: a red node with parent in red exists
 * return 5: volatile binary search properties
 *
 * when return !0, @blackheight & @maxdepth is uselsess
 * when return 0, @blackheight contains the tree's black height
 *
 * @maxdepth contains the max length of all simple roads from root to it's leaf nodes
 */
int util_rbtree_check(const util_rbtree_t *rbtree, int *blackheight, int *maxdepth);

/*
 * travel through a rb tree in sequence: left-root-right
 * you CAN NOT do any operations that will break the RB properties
 */
void util_rbtree_mid_travel(util_rbtree_t *rbtree, void(*opera)(util_rbtree_node_t *, void *), void *data);

#endif /* end __UTIL_RLTREE_H_ */
