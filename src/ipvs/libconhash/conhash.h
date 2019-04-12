
/* Copyright (C) 2010. sparkling.liang@hotmail.com. All rights reserved. */

#ifndef __CON_HASH_H_
#define __CON_HASH_H_

#include "configure.h"

#ifdef CONHASH_EXPORTS

/* windows platform DLL */
#if (defined (WIN32) || defined (__WIN32)) && (defined _USRDLL)
#define CONHASH_API __declspec(dllexport)
#else
#define CONHASH_API __declspec(dllimport)
#endif

#else /* Linux, or static lib */
#define CONHASH_API
#endif

#define NODE_FLAG_INIT  0x01 /* node is initialized */
#define NODE_FLAG_IN    0x02 /* node is added in the server */

/* nodes structure */
struct node_s
{
    char iden[64]; /* node name or some thing identifies the node */
    u_int replicas; /* number of replica virtual nodes */
    u_int flag;
    void *data;/*real data for consistent hash*/
};

/*
 * callback function to calculate hash value
 * @instr: input string
 */
typedef long (*conhash_cb_hashfunc)(const char *instr);

struct conhash_s;

/* export interfaces */
#ifdef  __cplusplus
extern "C" {
#endif
    /* initialize conhash library
     * @pfhash : hash function, NULL to use default MD5 method
     * return a conhash_s instance
     */
    CONHASH_API struct conhash_s* conhash_init(conhash_cb_hashfunc pfhash);

        /* finalize lib */
        CONHASH_API void conhash_fini(struct conhash_s *conhash, void (*node_fini)(struct node_s*));

        /* set node */
        CONHASH_API void conhash_set_node(struct node_s *node, const char *iden, u_int replica);

    /*
        * add a new node
        * @node: the node to add
        */
    CONHASH_API int conhash_add_node(struct conhash_s *conhash, struct node_s *node);

        /* remove a node */
    CONHASH_API int conhash_del_node(struct conhash_s *conhash, struct node_s *node);

        /*
     * update a node's virtual nodes
     * @replica: new replica of server
     * return 0 success, -1 failed
     */
    CONHASH_API int conhash_update_node(struct conhash_s *conhash, struct node_s *node, u_int replica);

    /*
        * lookup a server which object belongs to
        * @object: the input string which indicates an object
        * return the server_s structure, do not modify the value, or it will cause a disaster
        */
    CONHASH_API const struct node_s* conhash_lookup(const struct conhash_s *conhash, const char *object);

        /* some utility functions export*/
        CONHASH_API void  conhash_md5_digest(const u_char *instr, u_char digest[16]);
        /* get virtual node number in the hash */
    CONHASH_API u_int conhash_get_vnodes_num(const struct conhash_s *conhash);
        /*
        * get virtual nodes in ascending oder
        * @values, pointer to an array, stores all the nodes's hash value
        * @size, how many nodes to get, can't be less than the array size
        */
        CONHASH_API void  conhash_get_vnodes(const struct conhash_s *conhash, long *values, int size);

#ifdef  __cplusplus
}
#endif

#endif /* end __CON_HASH_H_ */
