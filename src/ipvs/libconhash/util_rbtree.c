
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#include "util_rbtree.h"

/* the NULL node of tree */
#define _NULL(rbtree) (&((rbtree)->null))

/* structues uesed to check a rb tree */
struct rbtree_check_s
{
    short rbh; /* rb height of the tree */
    short maxd; /* max depth of the tree */
    int fini; /* check failed ? */
    const util_rbtree_node_t *null; /* sentinel of the tree */
};

typedef struct rbtree_check_s rbtree_check_t;

static void rbtree_insert_fixup(util_rbtree_t *rbtree, util_rbtree_node_t *node);
static void rbtree_delete_fixup(util_rbtree_t *rbtree, util_rbtree_node_t *node);
static void rbtree_left_rotate(util_rbtree_t *rbtree, util_rbtree_node_t *node);
static void rbtree_right_rotate(util_rbtree_t *rbtree, util_rbtree_node_t *node);

void util_rbtree_init(util_rbtree_t *rbtree)
{
    if(rbtree != NULL)
    {
        util_rbt_black(_NULL(rbtree)); /* null MUST be black */
        rbtree->root = _NULL(rbtree);
        rbtree->size = 0;
    }
}

util_rbtree_node_t* util_rbsubtree_min(util_rbtree_node_t *node, util_rbtree_node_t *sentinel)
{
    if(node == sentinel) return NULL;
    while(node->left != sentinel) node = node->left;
    return node;
}

util_rbtree_node_t* util_rbsubtree_max(util_rbtree_node_t *node, util_rbtree_node_t *sentinel)
{
    if(node == sentinel) return NULL;
    while(node->right != sentinel) node = node->right;
    return node;
}

void util_rbtree_insert(util_rbtree_t *rbtree, util_rbtree_node_t *node)
{
    util_rbtree_node_t *x, *y;
    if((rbtree==NULL) || (node==NULL) || (node==_NULL(rbtree)))
    {
        return;
    }
    /* the tree is empty */
    if(rbtree->root == _NULL(rbtree))
    {
        rbtree->root = node;
        node->parent = _NULL(rbtree);
    }
    else /* find the insert position */
    {
        x = rbtree->root;
        while(x != _NULL(rbtree))
        {
            y = x;
            if(node->key < x->key) x = x->left;
            else x = x->right;
        }
        /* now y is node's parent */
        node->parent = y;
        if(node->key < y->key) y->left = node;
        else y->right = node;
    }

    /* initialize node's link & color */
    node->left = _NULL(rbtree);
    node->right = _NULL(rbtree);
    util_rbt_red(node);
    /* fix up insert */
    rbtree_insert_fixup(rbtree, node);
    rbtree->size++;
}

/* insert may violate the rbtree properties, fix up the tree */
void rbtree_insert_fixup(util_rbtree_t *rbtree, util_rbtree_node_t *node)
{
    util_rbtree_node_t *p, *u; /* u is the uncle node of node */
    while(util_rbt_isred(node->parent))
    {
        p = node->parent;
        if(p == p->parent->left) /* parent is the left child */
        {
            u = p->parent->right;
            if(util_rbt_isred(u)) /* case 1: p & u are red */
            {
                util_rbt_black(u);
                util_rbt_black(p);
                util_rbt_red(p->parent);
                node = p->parent;
            }
            else
            {
                if(node == p->right) /* case 2: p:read, u:black, node is right child */
                {
                    node = p;
                    rbtree_left_rotate(rbtree, node);
                    p = node->parent;
                }
                /* case 3: p:read, u:black, node is left child */
                util_rbt_black(p);
                util_rbt_red(p->parent);
                rbtree_right_rotate(rbtree, p->parent);
            }
        }
        else /* parent is the right child */
        {
            u = p->parent->left;
            if(util_rbt_isred(u))
            {
                util_rbt_black(u);
                util_rbt_black(p);
                util_rbt_red(p->parent);
                node = p->parent;
            }
            else
            {
                if(p->left == node)
                {
                    node = p;
                    rbtree_right_rotate(rbtree, node);
                    p = node->parent;
                }
                util_rbt_black(p);
                util_rbt_red(p->parent);
                rbtree_left_rotate(rbtree, p->parent);
            }
        }
    }
    /* mark root to black */
    util_rbt_black(rbtree->root);
}


void util_rbtree_delete(util_rbtree_t *rbtree, util_rbtree_node_t *node)
{
    int isblack;
    util_rbtree_node_t *temp, *subst;
    if((rbtree==NULL) || (node==NULL) || (node==_NULL(rbtree)))
    {
        return;
    }
    rbtree->size--;
    /* find deleted position, indicated by temp */
    if(node->left == _NULL(rbtree))
    {
        temp = node;
        subst = node->right;
    }
    else if(node->right == _NULL(rbtree))
    {
        temp = node;
        subst = node->left;
    }
    else /* right & left aren't null */
    {
        temp = util_rbsubtree_min(node->right, _NULL(rbtree));
        if(temp->left != _NULL(rbtree))
        {
            subst = temp->left;
        }
        else
        {
            subst = temp->right;
        }
    }
    if(temp == rbtree->root) /* temp is root */
    {
        rbtree->root = subst;
        util_rbt_black(subst);
        rbt_clear_node(temp);
        return;
    }
    isblack = util_rbt_isblack(temp);
    /* temp will be removed from it's position, rebuild links
     * NOTE: if temp->parent = node, then subst->parent is node
     * while node is the one to be delete, so relink subst's parent to temp
     * because temp will replace node's in the tree
     */
    if(temp->parent == node)
    {
        subst->parent = temp;
    }
    else
    {
        subst->parent = temp->parent;
    }

    if(temp == temp->parent->left)
    {
        temp->parent->left = subst;
    }
    else
    {
        temp->parent->right = subst;
    }
    /*
     * now temp is removed from the tree.
     * so we will make temp to replace node in the tree.
     */
    if(temp != node)
    {
        temp->parent = node->parent;
        if(node == rbtree->root) /* node maybe root */
        {
            rbtree->root = temp;
        }
        else
        {
            if(node->parent->left == node)
            {
                node->parent->left = temp;
            }
            else
            {
                node->parent->right = temp;
            }
        }
        temp->right = node->right;
        temp->left = node->left;
        if(temp->left != _NULL(rbtree))
        {
            temp->left->parent = temp;
        }
        if(temp->right != _NULL(rbtree))
        {
            temp->right->parent = temp;
        }
        temp->color = node->color;
    }
    rbt_clear_node(node);

    if(isblack)
    {
        /* temp is black, fix up delete */
        rbtree_delete_fixup(rbtree, subst);
    }
}

/* delete may violate the rbtree properties, fix up the tree */
void rbtree_delete_fixup(util_rbtree_t *rbtree, util_rbtree_node_t *node)
{
    int h = 0;
    util_rbtree_node_t *w;
    while((node != rbtree->root) && util_rbt_isblack(node))
    {
        h++;
        if(node == node->parent->left) /* node is left child */
        {
            w = node->parent->right;
            if(util_rbt_isred(w))
            {
                util_rbt_black(w);
                util_rbt_red(node->parent);
                rbtree_left_rotate(rbtree, node->parent);
                w = node->parent->right;
            }
            if(util_rbt_isblack(w->left) && util_rbt_isblack(w->right))
            {
                util_rbt_red(w);
                node = node->parent;
            }
            else
            {
                if(util_rbt_isblack(w->right))
                {
                    util_rbt_black(w->left);
                    util_rbt_red(w);
                    rbtree_right_rotate(rbtree, w);
                    w = node->parent->right;
                }
                w->color = node->parent->color;
                util_rbt_black(node->parent);
                util_rbt_black(w->right);
                rbtree_left_rotate(rbtree, node->parent);
                node = rbtree->root; /* to break loop */
            }
        }
        else /* node is right child */
        {
            w = node->parent->left;
            if(util_rbt_isred(w))
            {
                util_rbt_black(w);
                util_rbt_red(node->parent);
                rbtree_right_rotate(rbtree, node->parent);
                w = node->parent->left;
            }
            if(util_rbt_isblack(w->left) && util_rbt_isblack(w->right))
            {
                util_rbt_red(w);
                node = node->parent;
            }
            else
            {
                if(util_rbt_isblack(w->left))
                {
                    util_rbt_black(w->right);
                    util_rbt_red(w);
                    rbtree_left_rotate(rbtree, w);
                    w = node->parent->left;
                }
                w->color = node->parent->color;
                util_rbt_black(node->parent);
                util_rbt_black(w->left);
                rbtree_right_rotate(rbtree, node->parent);
                node = rbtree->root; /* to break loop */
            }
        }
    }
    util_rbt_black(node);
}

void rbtree_left_rotate(util_rbtree_t *rbtree, util_rbtree_node_t *node)
{
    util_rbtree_node_t *rc = node->right;
    util_rbtree_node_t *rclc = rc->left;
    /* make rc to replace node's position */
    rc->parent = node->parent;
    if(node == rbtree->root)
    {
        rbtree->root = rc;
    }
    else
    {
        if(node->parent->left == node) /* node is left child */
        {
            node->parent->left = rc;
        }
        else
        {
            node->parent->right = rc;
        }
    }
    /* make node to be rc's left child */
    node->parent = rc;
    rc->left = node;
    /* rc's left child to be node's right child */
    node->right = rclc;
    if(rclc != _NULL(rbtree))
    {
        rclc->parent = node;
    }
}

void rbtree_right_rotate(util_rbtree_t *rbtree, util_rbtree_node_t *node)
{
    util_rbtree_node_t *lc = node->left;
    util_rbtree_node_t *lcrc = lc->right;
    /* make lc to replace node's position */
    lc->parent = node->parent;
    if(node == rbtree->root)
    {
        rbtree->root = lc;
    }
    else
    {
        if(node->parent->left == node) /* node is left child */
        {
            node->parent->left = lc;
        }
        else
        {
            node->parent->right = lc;
        }
    }
    /* make node to be lc's right child */
    lc->right = node;
    node->parent = lc;
    /* lc's right child to be node's left child */
    node->left = lcrc;
    if(lcrc != _NULL(rbtree))
    {
        lcrc->parent = node;
    }
}

util_rbtree_node_t* util_rbtree_search(util_rbtree_t *rbtree, long key)
{
    if(rbtree != NULL)
    {
        util_rbtree_node_t *node = rbtree->root;
        util_rbtree_node_t *null = _NULL(rbtree);
        while(node != null)
        {
            if(key < node->key) node = node->left;
            else if(key > node->key) node = node->right;
            else if(node->key == key) return node;
        }
    }
    return NULL;
}

util_rbtree_node_t* util_rbtree_lookup(util_rbtree_t *rbtree, long key)
{
    if((rbtree != NULL) && !util_rbtree_isempty(rbtree))
    {
        util_rbtree_node_t *node = NULL;
        util_rbtree_node_t *temp = rbtree->root;
        util_rbtree_node_t *null = _NULL(rbtree);
        while(temp != null)
        {
            if(key <= temp->key)
            {
                node = temp; /* update node */
                temp = temp->left;
            }
            else if(key > temp->key)
            {
                temp = temp->right;
            }
        }
        /* if node==NULL return the minimum node */
        return ((node != NULL) ? node : util_rbtree_min(rbtree));
    }
    return NULL;
}

static void rbtree_check_subtree(const util_rbtree_node_t *node, rbtree_check_t *check,
                         int level, int curheight)
{
    if(check->fini) /* already failed */
    {
        return;
    }
    /* check node color */
    if(util_rbt_isblack(node))
    {
        curheight++;
    }
    else if(!util_rbt_isred(node))
    {
        check->fini = 2;
        return;
    }
    /* check left */
    if(node->left != check->null)
    {
        if(util_rbt_isred(node) && util_rbt_isred(node->left))
        {
            check->fini = 4;
            return;
        }
        if(node->key < node->left->key)
        {
            check->fini = 5;
            return;
        }
        rbtree_check_subtree(node->left, check, level+1, curheight);
    }
    else
    {
        goto __check_rb_height;
    }
    /* check right */
    if(node->right != check->null)
    {
        if(util_rbt_isred(node) && util_rbt_isred(node->right))
        {
            check->fini = 4;
            return;
        }
        if(node->key > node->right->key)
        {
            check->fini = 5;
            return;
        }
        rbtree_check_subtree(node->right, check, level+1, curheight);
    }
    else
    {
        goto __check_rb_height;
    }
    return;
__check_rb_height:
    if(check->rbh == 0)
    {
        check->rbh = curheight;
    }
    if(check->maxd < level)
    {
        check->maxd = level;
    }
    if(check->rbh != curheight)
    {
        check->fini = 3;
    }
}

int util_rbtree_check(const util_rbtree_t *rbtree, int *blackheight, int *maxdepth)
{
    rbtree_check_t check;
    if(rbtree->root == _NULL(rbtree))
    {
        return 0;
    }
    if(!util_rbt_isblack(rbtree->root))
    {
        return 1;
    }
    check.fini = check.maxd = check.rbh = 0;
    check.null = _NULL(rbtree);
    rbtree_check_subtree(rbtree->root, &check, 1, 0);
    if(blackheight)
    {
        *blackheight = check.rbh;
    }
    if(maxdepth)
    {
        *maxdepth = check.maxd;
    }
    return check.fini;
}

static void rbtree_mid_travel(util_rbtree_node_t *node, util_rbtree_node_t *sentinel,
                         void(*opera)(util_rbtree_node_t *, void *), void *data)
{
    if(node->left != sentinel)
    {
        rbtree_mid_travel(node->left, sentinel, opera, data);
    }
    opera(node, data);
    if(node->right != sentinel)
    {
        rbtree_mid_travel(node->right, sentinel, opera, data);
    }
}

void util_rbtree_mid_travel(util_rbtree_t *rbtree,
                            void(*opera)(util_rbtree_node_t *, void *), void *data)
{
    if((rbtree!=NULL) && !util_rbtree_isempty(rbtree))
    {
        rbtree_mid_travel(rbtree->root, _NULL(rbtree), opera, data);
    }
}
