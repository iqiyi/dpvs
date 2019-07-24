#include <stdio.h>
#include <string.h>
#include "inet.h"
#include "ipv4.h"
#include "ipv6.h"
#include "stats.h"
#include "conf/stats.h"

#ifndef STATS
#define STATS
#define RTE_LOGTYPE_STATS    RTE_LOGTYPE_USER1
#endif

#define STATS_TOPN 20

#define STATS_RING_SIZE  1024
#define STATS_INTERVAL   1024 

#define STATS_PKT_DIR_IN 0
#define STATS_PKT_DIR_OUT 1

#define STATS_TBL_BITS          20
#define STATS_TBL_SIZE          (1 << STATS_TBL_BITS)
#define STATS_TBL_MASK          (STATS_TBL_SIZE - 1)

#define HISTORY_LENGTH  10
#define RESOLUTION 2
int history_pos = 0;

time_t last_timestamp;
bool stats_disable = true;

typedef struct sorted_list_node_tag {
    struct sorted_list_node_tag* next;
    void* data;
} sorted_list_node;

typedef struct {
    sorted_list_node root;
    int (*compare)(void*, void*);
} sorted_list_type;

int sorted_list_num = 0;
sorted_list_type stats_sorted_list;

static struct list_head *stats_tbl;
static struct rte_ring *stats_ring[DPVS_MAX_LCORE];

#define this_inpkts_count   (RTE_PER_LCORE(inpkts_count))
#define this_outpkts_count  (RTE_PER_LCORE(outpkts_count))

static RTE_DEFINE_PER_LCORE(uint32_t, inpkts_count);
static RTE_DEFINE_PER_LCORE(uint32_t, outpkts_count);

static uint32_t stats_tlb_rnd; /* hash random */

typedef enum {
	HASH_STATUS_OK,
	HASH_STATUS_KEY_NOT_FOUND
} hash_status_enum;

struct stats_pkt {
	int af;
    uint32_t pkt_len;
    union inet_addr saddr;
	union inet_addr daddr;
	uint16_t src_port;
	uint16_t dst_port; 
	uint8_t proto;
	uint8_t dir;
    lcoreid_t cid;
} __rte_cache_aligned;

struct stats_entry {
	struct list_head	 list;

	uint8_t 			 af;
	uint8_t 			 proto;
	lcoreid_t			 cid;

	union inet_addr 	 saddr;
	union inet_addr 	 daddr;
	uint16_t			 sport;
	uint16_t			 dport;

    double long recv[HISTORY_LENGTH];
    double long sent[HISTORY_LENGTH];	
	
    double long total_recv;
    double long total_sent;
	int last_write;

} __rte_cache_aligned;


static inline uint32_t stats_tlb_hashkey(int af,
    const union inet_addr *saddr, uint16_t sport,
    const union inet_addr *daddr, uint16_t dport,
    uint32_t mask)
{
    switch (af) {
    case AF_INET:
        return rte_jhash_3words((uint32_t)saddr->in.s_addr,
                (uint32_t)daddr->in.s_addr,
                ((uint32_t)sport) << 16 | (uint32_t)dport,
                stats_tlb_rnd) & mask;

    case AF_INET6:
        {
            uint32_t vect[9];

            vect[0] = ((uint32_t)sport) << 16 | (uint32_t)dport;
            memcpy(&vect[1], &saddr->in6, 16);
            memcpy(&vect[5], &daddr->in6, 16);

            return rte_jhash_32b(vect, 9, stats_tlb_rnd) & mask;
        }

    default:
        RTE_LOG(DEBUG, STATS, "%s: hashing unsupported protocol %d\n", __func__, af);
        return 0;
    }
}

static hash_status_enum stats_entry_get(uint32_t hash, struct stats_pkt *param, struct stats_entry **out_entry)
{
	struct stats_entry *entry;
	
	list_for_each_entry(entry, &stats_tbl[hash], list) {
		if (entry->sport == param->src_port && entry->dport == param->dst_port
				&& inet_addr_equal(param->af, &entry->saddr, &param->saddr)
				&& inet_addr_equal(param->af, &entry->daddr, &param->daddr)
				&& entry->proto == param->proto
				&& entry->af == param->af) {
			/* hit */
	        *out_entry = entry;
			RTE_LOG(DEBUG, STATS,
					"%s: [hit]\n", __func__);	
			return HASH_STATUS_OK;
		}
	}
	RTE_LOG(DEBUG, STATS,
			"%s: [not found]\n", __func__);	

    return HASH_STATUS_KEY_NOT_FOUND;
}


static void history_rotate(void) 
{
	uint32_t hash = 0;
	struct stats_entry *entry, *nxt;
    history_pos = (history_pos + 1) % HISTORY_LENGTH;

    for(; hash < STATS_TBL_SIZE; hash++) {

		list_for_each_entry_safe(entry, nxt, &stats_tbl[hash], list) {

            /* no data in the last 20s */
            if (entry->last_write == history_pos) {
                list_del(&entry->list);
                if (entry->af == AF_INET) {
                    RTE_LOG(DEBUG, STATS,
                         "%s:[v4] [history_pos : %d, cid:%d, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u]\n",
                         __func__, history_pos, entry->cid, entry->proto, entry->saddr.in.s_addr,                                                                                entry->daddr.in.s_addr, entry->sport, entry->dport);
                }
                rte_free(entry);
			} else {
				entry->total_recv -= entry->recv[history_pos];
				entry->total_sent -= entry->sent[history_pos];
				entry->recv[history_pos] = 0;
				entry->sent[history_pos] = 0;
			}
		}
	}
}

static int stats_entry_compare(void* aa, void* bb) {
    struct stats_entry * a = (struct stats_entry *)aa;
    struct stats_entry * b = (struct stats_entry *)bb;

	return (a->total_recv + a->total_sent) > (b->total_recv + b->total_sent);
}

static void sorted_list_initialise(sorted_list_type* list) {
    list->root.next = NULL;
}

static void insert_topN_list(struct stats_entry *entry)
{
    sorted_list_node *node, *p, *first;
    struct stats_entry *data;

    p = &(stats_sorted_list.root);

	if (sorted_list_num == STATS_TOPN && stats_sorted_list.compare(p->next->data, entry)) {   
		RTE_LOG(DEBUG, STATS,
			"%s: no need to insert\n", __func__);
		return;
	}

    while (p->next != NULL && stats_sorted_list.compare(entry, p->next->data) > 0) {
        p = p->next;
    } 

    node = rte_zmalloc(NULL, sizeof(*node), RTE_CACHE_LINE_SIZE);
	if (node == NULL) {
		RTE_LOG(ERR, STATS,
				"%s: no memory\n", __func__);
		return;
	}

    node->next = p->next;
    node->data = entry;
    p->next = node;
    RTE_LOG(DEBUG, STATS,
        "%s: [insert list]cid : %d, sp : %u, dp : %u\n", 
        __func__, entry->cid, entry->sport, entry->dport);
    if(sorted_list_num < STATS_TOPN)
	    sorted_list_num++;
    else {
        /* free the first node */
	    p = &(stats_sorted_list.root);
        first = p->next;
	
        data = (struct stats_entry *)first->data;
        RTE_LOG(DEBUG, STATS,
            "%s: [free first entry]cid : %d, sp : %u, dp : %u\n", 
             __func__, data->cid, data->sport, data->dport);
        p->next = first->next;

		rte_free(first);
	}
}

static void stats_sort_topN(void)
{
	uint32_t hash = 0;
	struct stats_entry *entry, *nxt;

    for(; hash < STATS_TBL_SIZE; hash++) {

		list_for_each_entry_safe(entry, nxt, &stats_tbl[hash], list) {
		    insert_topN_list(entry);
		}
	}
}

static void stats_addr_cpy(int af, 	union inet_addr *daddr, union inet_addr *saddr)
{
	if (af == AF_INET) {
		daddr->in.s_addr = saddr->in.s_addr;
	} else if (af == AF_INET6) {
		memcpy(daddr->in6.s6_addr, saddr->in6.s6_addr, 16);
	} else {
		RTE_LOG(DEBUG, STATS,
				"%s: unsupported\n", __func__);
	}    
}

int stats_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
                             void **out, size_t *outsize)
{
    struct stats_param_array *array;
    sorted_list_node *node, *p;
	struct stats_entry *entry;
    uint32_t off;

    if (stats_disable) {
        RTE_LOG(DEBUG, STATS,
            "%s: stats disable\n",  __func__);      
        return EDPVS_OK;
    }   

    if (!conf || size < sizeof(struct stats_param) || !out || !outsize)
        return EDPVS_INVAL;

    /* sort stats */
	stats_sort_topN();

    *outsize = sizeof(struct stats_param_array) + \
               sorted_list_num * sizeof(struct stats_param);
    *out = rte_calloc(NULL, 1, *outsize, RTE_CACHE_LINE_SIZE);
    if (!(*out)) {
		RTE_LOG(ERR, STATS,
						"%s: no memory \n", __func__);
        return EDPVS_NOMEM;
    }

    array = *out;
    array->nstats = sorted_list_num;
    off = 0;

    p = &(stats_sorted_list.root);
    while (p->next != NULL && off < sorted_list_num) {
        node = p->next;
        p->next = node->next;	

	    entry = (struct stats_entry *)node->data;
		array->stats[off].af = entry->af;
		array->stats[off].proto = entry->proto;
		array->stats[off].cid = entry->cid;
		stats_addr_cpy(entry->af, &array->stats[off].saddr, &entry->saddr);
		stats_addr_cpy(entry->af, &array->stats[off].daddr, &entry->daddr);
		array->stats[off].sport = entry->sport;
		array->stats[off].dport = entry->dport;
		array->stats[off].total_recv = entry->total_recv * STATS_INTERVAL;
		array->stats[off].total_sent = entry->total_sent * STATS_INTERVAL;
       
        if (AF_INET == entry->af) {
            RTE_LOG(DEBUG, STATS,"%s: sip = %s, sport = %u\n", __func__, inet_ntoa(array->stats[off].saddr.in), ntohs(entry->sport));
            RTE_LOG(DEBUG, STATS,"%s: dip = %s, dport = %u\n", __func__, inet_ntoa(array->stats[off].daddr.in), ntohs(entry->dport));
        } else if (AF_INET6 == entry->af) {
                char src_addr[INET6_ADDRSTRLEN];
                char dst_addr[INET6_ADDRSTRLEN];

                inet_ntop(AF_INET6, &entry->saddr.in6, src_addr, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, &entry->daddr.in6, dst_addr, INET6_ADDRSTRLEN);

                RTE_LOG(DEBUG, STATS,"%s: sip = %s sport = %u, dip = %s, dport = %u\n",
                     __func__, src_addr, ntohs(entry->sport), dst_addr, ntohs(entry->dport));
        } else {
            RTE_LOG(DEBUG, STATS, "%s: unsupported\n", __func__);
        }
        
        RTE_LOG(DEBUG, STATS,
            "%s: off : %u, cid : %d, proto: %u, total_recv: %Lf,  total_sent : %Lf\n", 
            __func__, off, entry->cid, entry->proto, array->stats[off].total_recv, array->stats[off].total_sent);
        
        rte_free(node);

		off++;
    }

    sorted_list_num = 0;
    return EDPVS_OK;
}


void stats_process_ring(void)
{    
    int i;
    uint16_t nb_rb;
	uint32_t hash;
	lcoreid_t cid;
    struct stats_pkt *param;
	struct stats_pkt *params[NETIF_MAX_PKT_BURST];
	struct stats_entry *entry = NULL;

    time_t t;

    if (likely(stats_disable)) {		
        return;
    }	

    t = time(NULL);
    if(t - last_timestamp >= RESOLUTION) {
        history_rotate();
        last_timestamp = t;
    }
	
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
	    if (!rte_lcore_is_enabled(cid)) {
		    continue;
	    }

	    nb_rb = rte_ring_dequeue_burst(stats_ring[cid], (void **)params,
									  NETIF_MAX_PKT_BURST, NULL);

		if (nb_rb > 0) {			
			for (i = 0; i < nb_rb; i++) {
			    param = params[i];

				hash = stats_tlb_hashkey(param->af, &param->saddr, param->src_port, &param->daddr, 
					param->dst_port, STATS_TBL_MASK);

				if (stats_entry_get(hash, param, &entry) == HASH_STATUS_KEY_NOT_FOUND) {

					entry = rte_zmalloc(NULL, sizeof(struct stats_entry), RTE_CACHE_LINE_SIZE);
					if (entry == NULL) {
						RTE_LOG(ERR, STATS,
								"%s: no memory\n", __func__);
						continue;
					}
					
					memset(entry, 0, sizeof(struct stats_entry));
					entry->af = param->af;
					entry->cid = param->cid;
					entry->proto = param->proto;
					stats_addr_cpy(param->af, &entry->saddr, &param->saddr);
					stats_addr_cpy(param->af, &entry->daddr, &param->daddr);
					entry->sport = param->src_port;
					entry->dport = param->dst_port;
			
					list_add(&entry->list, &stats_tbl[hash]);                 
				}
                
                if (param->af == AF_INET) {
				    RTE_LOG(DEBUG, STATS,
						"%s:[v4] dequeue stats_ring[cid:%d, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u, len:%u]\n",
						__func__, entry->cid, entry->proto, entry->saddr.in.s_addr, 
						entry->daddr.in.s_addr, entry->sport, entry->dport, param->pkt_len);
                } else {
                    RTE_LOG(DEBUG, STATS,
                         "%s:[v6] dequeue stats_ring[cid:%d, dir:%d, proto:%u, src:%08X %08X %08X %08X, dst:%08X %08X %08X %08X, sp:%u, dp:%u, len:%u]\n",
                         __func__, entry->cid, param->dir, entry->proto, 
                         entry->saddr.in6.s6_addr32[0], entry->saddr.in6.s6_addr32[1],
                         entry->saddr.in6.s6_addr32[2], entry->saddr.in6.s6_addr32[3],
                         entry->daddr.in6.s6_addr32[0],entry->daddr.in6.s6_addr32[1],
                         entry->daddr.in6.s6_addr32[2],entry->daddr.in6.s6_addr32[3],
                         entry->sport, entry->dport, param->pkt_len);
                
                }

				/* Update record */
				entry->last_write = history_pos;
				if (param->dir == STATS_PKT_DIR_IN) {
					entry->recv[history_pos] += param->pkt_len;
					entry->total_recv += param->pkt_len;
                    RTE_LOG(DEBUG, STATS,
                        "%s: history_pos: %d, recv : %Lf, total_recv : %Lf\n", __func__, history_pos, entry->recv[history_pos], entry->total_recv);

                } else {
					entry->sent[history_pos] += param->pkt_len;
					entry->total_sent += param->pkt_len;

                    RTE_LOG(DEBUG, STATS,
                        "%s: history_pos: %d: sent : %Lf, total_sent: %Lf\n", __func__, history_pos, entry->sent[history_pos], entry->total_sent);
				}				
			}
		}
    }
}

static int stats_pkt_deliver(int af, struct rte_mbuf *mbuf, uint8_t dir)
{
	int ret;
	struct stats_pkt *pkt;
	__be16 _ports[2], *ports;
	lcoreid_t cid = rte_lcore_id();

	if (af == AF_INET) {
		struct ipv4_hdr *ip4h = ip4_hdr(mbuf);

		if (unlikely(ip4h->next_proto_id != IPPROTO_TCP &&
					 ip4h->next_proto_id != IPPROTO_UDP)) {
			RTE_LOG(DEBUG, STATS,
				"%s: unspported proto[core: %d, proto: %d]\n",
				__func__, cid, ip4h->next_proto_id);
			return EDPVS_NOPROT;
		}

	    ports = mbuf_header_pointer(mbuf, ip4_hdrlen(mbuf), sizeof(_ports), _ports);
	    if (!ports) {
			RTE_LOG(ERR, STATS,
					"%s: invalid pkt[%d, %d]\n",
					__func__, cid, dir);
			return EDPVS_INVPKT;
		}	
		
		pkt = rte_zmalloc("stats_inpkt", sizeof(struct stats_pkt), RTE_CACHE_LINE_SIZE);
		if (pkt == NULL) {
			RTE_LOG(ERR, STATS,
					"%s: no memory[%d, %d]\n",
					__func__, cid, dir);
			return EDPVS_NOMEM;
		}
		
		pkt->af = AF_INET;
		pkt->cid = cid;
		pkt->dir = dir;
		pkt->proto = ip4h->next_proto_id;
		pkt->saddr.in.s_addr = ip4h->src_addr;
		pkt->daddr.in.s_addr = ip4h->dst_addr;
		pkt->src_port = ports[0];
		pkt->dst_port = ports[1];
		pkt->pkt_len = mbuf->pkt_len;
		RTE_LOG(DEBUG, STATS,
				"%s:[v4] enqueued to stats_ring[cid:%d, dir:%d, proto:%u, src:%08X, dst:%08X, sp:%u, dp:%u, len:%u]\n",
				__func__, cid, dir, pkt->proto, ip4h->src_addr, ip4h->dst_addr, pkt->src_port, pkt->dst_port, pkt->pkt_len);

	} else if (af == AF_INET6) {
		struct ip6_hdr *ip6h = ip6_hdr(mbuf);
		uint8_t ip6nxt = ip6h->ip6_nxt;

		if (unlikely(ip6nxt != IPPROTO_TCP &&
					 ip6nxt != IPPROTO_UDP)) {
			RTE_LOG(DEBUG, STATS,
				"%s: unspported proto[core: %d, proto: %d]\n",
				__func__, cid, ip6nxt);
			return EDPVS_NOPROT;
		}
        
		ports = mbuf_header_pointer(mbuf, ip6_hdrlen(mbuf), sizeof(_ports), _ports);
		if (!ports) {
			RTE_LOG(ERR, STATS,
					"%s: invalid pkt[%d, %d]\n",
					 __func__, cid, dir);
			return EDPVS_INVPKT;
		}	 
		
		pkt = rte_zmalloc("stats_inpkt", sizeof(struct stats_pkt), RTE_CACHE_LINE_SIZE);
		if (pkt == NULL) {
			RTE_LOG(ERR, STATS,
					"%s: no memory[%d, %d]\n",
					__func__, cid, dir);
			return EDPVS_NOMEM;
		}
		
		pkt->af = AF_INET6;
		pkt->cid = cid;
		pkt->dir = dir;
		pkt->proto = ip6nxt;
		pkt->saddr.in6 = ip6h->ip6_src;
		pkt->daddr.in6 = ip6h->ip6_dst;
		pkt->src_port = ports[0];
		pkt->dst_port = ports[1];
		pkt->pkt_len = mbuf->pkt_len;

		RTE_LOG(DEBUG, STATS,
				"%s:[v6] enqueued to stats_ring[cid:%d, dir:%d, proto:%u, src:%08X %08X %08X %08X, dst:%08X %08X %08X %08X, sp:%u, dp:%u, len:%u]\n",
				__func__, cid, dir, pkt->proto, 
				pkt->saddr.in6.s6_addr32[0], pkt->saddr.in6.s6_addr32[1],
				pkt->saddr.in6.s6_addr32[2], pkt->saddr.in6.s6_addr32[3],
			    pkt->daddr.in6.s6_addr32[0],pkt->daddr.in6.s6_addr32[1],
			    pkt->daddr.in6.s6_addr32[2],pkt->daddr.in6.s6_addr32[3],
		        pkt->src_port, pkt->dst_port, pkt->pkt_len);
		
    } else {
//#ifdef CONFIG_DPVS_IPVS_DEBUG
		RTE_LOG(DEBUG, STATS,
			"%s: err af\n",	__func__);
//#endif
        return EDPVS_INVPKT;
	}	

	ret = rte_ring_enqueue(stats_ring[cid], pkt);
	if (ret < 0) {
		RTE_LOG(DEBUG, STATS,
			"%s: failed to enqueue stats_ring[%d]\n",
			__func__, cid);
		rte_free(pkt);
		return EDPVS_DROP;
	}

//#ifdef CONFIG_DPVS_IPVS_DEBUG
	RTE_LOG(DEBUG, STATS,
		"%s: enqueued to stats_ring[%d]\n",
		__func__, cid);
//#endif

    return EDPVS_OK;
}

int stats_pkt_in(int af, struct rte_mbuf *mbuf)
{
    if (likely(stats_disable)) {
		RTE_LOG(DEBUG, STATS,
			"%s: stats disable\n", __func__);		
        return EDPVS_OK;
    }		

	this_inpkts_count++;
	if (this_inpkts_count % STATS_INTERVAL == 0) {

        stats_pkt_deliver(af, mbuf, STATS_PKT_DIR_IN);
    }

	return EDPVS_OK;
}

int stats_pkt_out(int af, struct rte_mbuf *mbuf)
{
    if (likely(stats_disable)) {
		RTE_LOG(DEBUG, STATS,
			"%s: stats disable\n", __func__);		
        return EDPVS_OK;
    }		

	this_outpkts_count++;
	if (this_outpkts_count % STATS_INTERVAL == 0) {

        stats_pkt_deliver(af, mbuf, STATS_PKT_DIR_OUT);
    }

	return EDPVS_OK; 
}


/*
 * master core allocates stats rings with the other lcores espectively.
 */
static int stats_ring_create(void)
{
    char name_buf[RTE_RING_NAMESIZE];
    int socket_id;
	lcoreid_t cid;

    socket_id = rte_socket_id();

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
            continue;
        }

        snprintf(name_buf, RTE_RING_NAMESIZE,
            "stat_ring[%d]", cid);

        stats_ring[cid] =
            rte_ring_create(name_buf, STATS_RING_SIZE, socket_id,
                            RING_F_SP_ENQ | RING_F_SC_DEQ);

        if (!stats_ring[cid]) {
            RTE_LOG(ERR, STATS,
                "%s: failed to create stat_ring[%d]\n",
                 __func__, cid);
            return EDPVS_NOMEM;
        }

        RTE_LOG(DEBUG, STATS,
	        "%s: success to create stat_ring[%d]\n",
	        __func__, cid);
    }

    return EDPVS_OK;
}

int stats_enable_func(void)
{
	int i;
    int err;

    if (stats_disable == false) {
        return EDPVS_OK;
    }

    err = stats_ring_create();
    if (err != EDPVS_OK) {
        return err;
    }

    stats_tbl = rte_malloc_socket(NULL, sizeof(struct list_head) * STATS_TBL_SIZE,
            RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (!stats_tbl) {
        RTE_LOG(ERR, STATS,
            "%s: rte_malloc_socket null\n",
            __func__);
		return EDPVS_NOMEM;
	}

    for (i = 0; i < STATS_TBL_SIZE; i++)
        INIT_LIST_HEAD(&stats_tbl[i]);
	
	stats_disable = false;
	RTE_LOG(DEBUG, STATS,
		"%s: stats_disable[%d]\n",
		__func__, stats_disable);

    return EDPVS_OK;
}

static void stats_variable_reset(void)
{
	history_pos = 0;	
    sorted_list_num = 0;	
	
	this_inpkts_count = 0;
	this_outpkts_count = 0;
}

static void stats_ring_free(void)
{
    lcoreid_t cid;

    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
        if (!rte_lcore_is_enabled(cid)) {
             continue;
        }
        rte_ring_free(stats_ring[cid]);
        RTE_LOG(DEBUG, STATS,
            "%s: stats_ring free[%d]\n",
            __func__, cid);
    }
}


int stats_disable_func(void)
{
	uint32_t hash = 0;
    int i;
    uint16_t nb_rb;
	lcoreid_t cid;
    struct stats_pkt *param;
	struct stats_pkt *params[NETIF_MAX_PKT_BURST];
	struct stats_entry *entry, *nxt;
	sorted_list_node *node, *p;
	int count = 0;

    if (stats_disable == true) {
        return EDPVS_OK;
    }

	stats_disable = true;

    /* dequeue stats ring and free elements */
    for (cid = 0; cid < DPVS_MAX_LCORE; cid++) {
	    if (!rte_lcore_is_enabled(cid)) {
		    continue;
	    }

	    nb_rb = rte_ring_dequeue_burst(stats_ring[cid], (void **)params,
									  NETIF_MAX_PKT_BURST, NULL);

		while (nb_rb > 0) {		
			count += nb_rb;
			for (i = 0; i < nb_rb; i++) {
			    param = params[i];
                rte_free(param);
			}
			
		    nb_rb = rte_ring_dequeue_burst(stats_ring[cid], (void **)params,
							  NETIF_MAX_PKT_BURST, NULL);
		}
		
		RTE_LOG(DEBUG, STATS,
			"%s: stats ring[%d] free [%d] pkts\n",
			__func__, cid, count);

		count = 0;
		
    }	

	/* free stats ring */
	stats_ring_free();

    count = 0;
    /* delete and free all entry added to stats_tbl */
    for(; hash < STATS_TBL_SIZE; hash++) {
		list_for_each_entry_safe(entry, nxt, &stats_tbl[hash], list) {
            list_del(&entry->list);
            rte_free(entry);
			count++;
		}
	}

	RTE_LOG(DEBUG, STATS,
		"%s: stats_tbl free [%d]\n",
		__func__, count);

    /* free tlb */
    if (stats_tbl) {
        rte_free(stats_tbl);
    }

	count = 0;

    /* free sorted list */
    p = &(stats_sorted_list.root);
    while (p->next != NULL) {
        node = p->next;
	    p->next = node->next;
		rte_free(node);	
		count++;
    } 
	
	RTE_LOG(DEBUG, STATS,
		"%s: stats_sorted_list free [%d]\n",
		__func__, count);
    
	stats_variable_reset();

    return EDPVS_OK;
}

static void stats_sorted_list_init(void) {
    stats_sorted_list.compare = &stats_entry_compare;
    sorted_list_initialise(&stats_sorted_list);
}

static int stats_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
     switch (opt) {
     case SOCKOPT_SET_STATS_ADD:
                            
          RTE_LOG(DEBUG, STATS,
              "%s: enable\n", __func__);
          return stats_enable_func(); 
     case SOCKOPT_SET_STATS_DEL:
          RTE_LOG(DEBUG, STATS,
              "%s: disable\n", __func__);
          return stats_disable_func(); 

     default:
          RTE_LOG(ERR, STATS,
               "%s: NOTSUPP\n", __func__);
          return EDPVS_NOTSUPP;
     }
}


static struct dpvs_sockopts stats_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_STATS_ADD,
    .set_opt_max    = SOCKOPT_SET_STATS_DEL,
    .set            = stats_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_STATS_SHOW,
    .get_opt_max    = SOCKOPT_GET_STATS_SHOW,
    .get            = stats_sockopt_get,
};

int stats_init(void)
{
    int err;
	
	stats_disable = true;

	stats_tlb_rnd = (uint32_t)random();

	stats_sorted_list_init();

    if ((err = sockopt_register(&stats_sockopts)) != EDPVS_OK)
        return err;

    return EDPVS_OK;
}
