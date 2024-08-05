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
 * Jul 2024, yuwenchao@qiyi.com, Initial
 */

#include <limits.h>
#include <sys/utsname.h>
#include "list.h"
#include "timer.h"
#include "ctrl.h"
#include "netif.h"
#include "netif_addr.h"
#include "lldp.h"
#include "conf/lldp.h"

#define RTE_LOGTYPE_LLDP        RTE_LOGTYPE_USER1

#define DPVS_LLDP_PDU_MAX         1500
#define DPVS_LLDP_TTL_DEFAULT     120
#define DPVS_LLDP_TX_INTERVAL     30
#define DPVS_LLDP_UPDATE_INTERVAL 600

#define DPVS_LLDP_TL_TYPE(tl)   ((rte_be_to_cpu_16(tl) & 0xfe00) >> 9)
#define DPVS_LLDP_TL_LEN(tl)    ((rte_be_to_cpu_16(tl) & 0x01ff))
#define DPVS_LLDP_TL(type, len) (rte_cpu_to_be_16((((type) & 0x7f) << 9) | ((len) & 0x1ff)))

#define lldp_type_equal(t1, t2) (((t1).type == (t2).type) && ((t1).subtype == (t2).subtype))

/* helper macro used in lldp_type_ops::dump
 * @buf: target string buffer, must be an array
 * @pos: start position for this snprintf, must be an initialized integer variable
 * */
#define lldp_dump_snprintf(buf, pos, fmt, ...)                                      \
    do {                                                                            \
        int res = snprintf(&(buf)[pos], sizeof(buf) - pos, fmt, ##__VA_ARGS__);     \
        if (unlikely(res < 0))                                                      \
            return EDPVS_IO;                                                        \
        (pos) += res;                                                               \
        if ((pos) >= sizeof(buf))                                                   \
            return EDPVS_NOROOM;                                                    \
    } while (0)

/* helper macro used ihn lldp_type_ops::dump
 * @buf: target string buffer, must be an array
 * @pos: start position for this snprintf, must be an initialized integer variable
 * @s: non-null-terminated string (use lldp_dump_snprintf for null-terminated string)
 * @n: length of s
 * @ends: ending string appended into buf
 * */
#define lldp_dump_strcpy(buf, pos, s, n, ends)                                      \
    do {                                                                            \
        int i, endslen = strlen(ends);                                              \
        if (unlikely((endslen + (n)) >= (sizeof(buf) - (pos))))                     \
            return EDPVS_NOROOM;                                                    \
        rte_memcpy(&(buf)[pos], s, n);                                              \
        (pos) += (n);                                                               \
        for (i = 0; i < endslen; i++)                                               \
            (buf)[(pos)++] = ends[i];                                               \
        (buf)[pos] = '\0';                                                          \
    } while (0)

const struct rte_ether_addr LLDP_ETHER_ADDR_DST = {
    .addr_bytes = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E}
};

/*
 * LLDP is processed only on master lcore, all data structures are free of lock
 */

typedef struct {
    uint8_t type;
    uint32_t subtype;
} lldp_type_t;

struct lldp_port {
    struct netif_port   *dev;
    struct list_head    head;   /* lldp_entry list head, sorted by lldp type */
    struct list_head    node;
    struct dpvs_timer   timer;
    uint32_t            timeout;
    uint16_t            entries;
    uint16_t            neigh;  /* DPVS_LLDP_NODE_xxx */
};

struct lldp_entry {
    struct list_head    node;
    struct lldp_port    *port;
    uint8_t             stale;
    lldp_type_t         type;
    uint16_t            len;    /* host endian */

    /* lldp pdu */
    uint16_t        typelen;    /* network endian */
    char            value[0];
};

struct lldp_type_ops {
    uint8_t type;

    /*
     * Parse LLDP type and subtype from LLDP PDU
     * @params
     *   llpdu: lldp pdu
     *   type:  where to store the parsed type id, must not be NULL
     *   len:   where to store the parse data len for the type, can be NULL
     * @return
     *   DPVS error code num
     * */
    int (*parse_type)(const char *llpdu, lldp_type_t *type, uint16_t *len);

    /*
     * Generate LLDP PDU, and store it to lldpdu
     * @params
     *   dev:     physical netif port
     *   subtype: subtype of the LLDP PDU
     *   lldpdu:  lldp pdu buffer
     *   len:     buffer size
     * @return
     *   the lldp pdu length on success or buffer not big enough
     *   dpvs negative error code on error
     * */
    int (*local_lldp)(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len);

    /*
     * Translate LLDP PDU, store the translated message into buf.
     * @params
     *   e:     lldp entry
     *   buf:   message buffer
     *   len:   message buffer size
     * @return (similar to "snprintf")
     *   the message length on success or buffer not big enough
     *   negative error code on error
     *   the returned message always teminates with '\0'.
     * */
    int (*dump)(const struct lldp_entry *e, char *buf, size_t len);

    /*
     * Actions to take after lldp pdu changed (add, update)
     * @params:
     *   entry: the newly added entry
     * @return
     *   dpvs error code
     * */
    int (*on_change)(const struct lldp_entry *entry);
};

static int lldp_enable = 0;
static struct dpvs_timer lldp_xmit_timer;
static struct dpvs_timer lldp_update_timer;

static char lldp_sn[256];
static struct utsname lldp_uname;

static struct list_head lldp_ports[DPVS_LLDP_NODE_MAX];
static struct lldp_type_ops *lldp_types[DPVS_LLDP_TYPE_MAX] = { NULL };

static int lldp_xmit_start(void);
static int lldp_xmit_stop(void);

void dpvs_lldp_enable(void)
{
    int err;

    if (lldp_enable)
        return;

    if (dpvs_state_get() == DPVS_STATE_NORMAL) {
        if ((err = lldp_xmit_start()) != EDPVS_OK) {
            RTE_LOG(ERR, LLDP, "%s: fail to enable lldp -- %s\n",
                    __func__, dpvs_strerror(err));
            return;
        }
    }

    lldp_enable = 1;
}

void dpvs_lldp_disable(void)
{
    int err;

    if (!lldp_enable)
        return;

    if (dpvs_state_get() == DPVS_STATE_NORMAL) {
        if ((err = lldp_xmit_stop()) != EDPVS_OK) {
            RTE_LOG(ERR, LLDP, "%s: fail to disable lldp -- %s\n",
                    __func__, dpvs_strerror(err));
            return;
        }
    }

    lldp_enable = 0;
}

bool dpvs_lldp_is_enabled(void)
{
    return !!lldp_enable;
}

static int lldp_serail_number_init(void)
{
    FILE *fp;
    char *ptr;

    fp = fopen("/sys/class/dmi/id/product_serial", "r");
    if (!fp) {
        RTE_LOG(WARNING, LLDP, "%s: fail to open serial number file\n", __func__);
        snprintf(lldp_sn, sizeof(lldp_sn), "%s", "Unknown");
        return EDPVS_SYSCALL;
    }

    if (!fgets(lldp_sn, sizeof(lldp_sn), fp)) {
        RTE_LOG(WARNING, LLDP, "%s: fail to read serial number file\n", __func__);
        snprintf(lldp_sn, sizeof(lldp_sn), "%s", "Unknown");
        return EDPVS_IO;
    }

    /* remove the tailing LF character */
    ptr = strrchr(lldp_sn, '\n');
    if (ptr)
        *ptr = '\0';

    return EDPVS_OK;
}

static inline int lldp_type_cmp(lldp_type_t *t1, lldp_type_t *t2)
{
    if (t1->type < t2->type)
        return -1;
    if (t1->type > t2->type)
        return 1;
    if (t1->subtype < t2->subtype)
        return -1;
    if (t1->subtype > t2->subtype)
        return 1;
    return 0;
}

static int lldp_type_register(struct lldp_type_ops *ops)
{
    if (!ops || ops->type >= DPVS_LLDP_TYPE_MAX)
        return EDPVS_INVAL;

    if (lldp_types[ops->type] != NULL)
        return EDPVS_EXIST;

    if (!ops->parse_type || !ops->dump)
        return EDPVS_INVAL;

    lldp_types[ops->type] = ops;
    return EDPVS_OK;
}

static int lldp_type_unregister(struct lldp_type_ops *ops)
{
    if (!ops || ops->type >= DPVS_LLDP_TYPE_MAX)
        return EDPVS_INVAL;

    if (!lldp_types[ops->type])
        return EDPVS_NOTEXIST;

    lldp_types[ops->type] = NULL;
    return EDPVS_OK;
}

static struct lldp_type_ops *lldp_type_get(lldp_type_t type)
{
    if (type.type >= DPVS_LLDP_TYPE_MAX)
        return NULL;
    return lldp_types[type.type];
}

static int lldp_parse_type_default(const char *lldpdu, lldp_type_t *type, uint16_t *len)
{
    assert(NULL != type);

    type->type = DPVS_LLDP_TL_TYPE((uint16_t)(*lldpdu));
    type->subtype = 0;
    if (!LLDP_TYPE_VALID(type->type)) {
        type->type = 0;
        return EDPVS_INVAL;
    }
    if (len)
        *len = DPVS_LLDP_TL_LEN(*((uint16_t *)lldpdu));

    return EDPVS_OK;
}

static int lldp_local_pdu_end(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    uint16_t *typelen = (uint16_t *)buf;

    if (len >= 2)
        *typelen = DPVS_LLDP_TL(LLDP_TYPE_END, 0);
    else
        memset(buf, 0, len);
    return 2;
}

static int lldp_dump_end(const struct lldp_entry *e, char *buf, size_t len)
{
    return snprintf(buf, len, "%s\n", "End of LLDPDU TLV");
}

static int lldp_parse_type_chassis_id(const char *lldpdu, lldp_type_t *type, uint16_t *len)
{
    assert(type != NULL);

    type->type = DPVS_LLDP_TL_TYPE((uint16_t)(*lldpdu));
    if (!LLDP_TYPE_VALID(type->type)) {
        type->type = 0;
        return EDPVS_INVAL;
    }

    type->subtype = *(lldpdu + 2);
    if (!LLDP_CHASSIS_ID_VALID(type->subtype)) {
        type->subtype = 0;
        return EDPVS_INVAL;
    }

    if (len)
        *len = DPVS_LLDP_TL_LEN(*((uint16_t *)lldpdu));

    return EDPVS_OK;
}

static int lldp_local_pdu_chassis_id(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    if (len >= 2 + 7) {
        *((uint16_t *)buf) = DPVS_LLDP_TL(LLDP_TYPE_CHASSIS_ID, 7);
        buf[2]  = LLDP_CHASSIS_ID_MAC_ADDRESS;
        rte_memcpy(&buf[3], &dev->addr, 6);
    } else {
        memset(buf, 0, len);
    }
    return 2 + 7;
}

static int lldp_dump_chassis_id(const struct lldp_entry *e, char *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)e->value;    /* Chassis ID Type */
    int pos = 0;
    char tbuf[512], ipbuf[64];

    lldp_dump_snprintf(tbuf, pos, "%s (%d)\n", "Chassis ID TLV", e->type.type);

    assert(e->type.subtype == *ptr);
    ++ptr;                                              /* Chassis ID Data */
    switch (e->type.subtype) {
        case LLDP_CHASSIS_ID_CHASSIS_COMPONENT:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tChassis Component: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_CHASSIS_ID_INTERFACE_ALIAS:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tInterface Alias: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_CHASSIS_ID_PORT_COMPONENT:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tPort Component: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_CHASSIS_ID_MAC_ADDRESS:
            if (unlikely(e->len < 7))
                return EDPVS_INVPKT;
            lldp_dump_snprintf(tbuf, pos, "\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
            break;
        case LLDP_CHASSIS_ID_NETWORK_ADDRESS:
            switch (*ptr) {
                case LLDP_ADDR_IPV4:
                    if (unlikely(e->len < 6))
                        return EDPVS_INVPKT;
                    lldp_dump_snprintf(tbuf, pos, "\tIPv4: %s\n", inet_ntop(AF_INET, ptr + 1,
                                ipbuf, sizeof(ipbuf)) ?: "Unknown");
                    break;
                case LLDP_ADDR_IPV6:
                    if (unlikely(e->len < 18))
                        return EDPVS_INVPKT;
                    lldp_dump_snprintf(tbuf, pos, "\tIPv6: %s\n", inet_ntop(AF_INET6, ptr + 1,
                                ipbuf, sizeof(ipbuf)) ?: "Unknown");
                    break;
                default:
                    if (unlikely(e->len <= 2))
                        return EDPVS_INVPKT;
                    lldp_dump_snprintf(tbuf, pos, "\tNetwork Address Type %d:", *ptr);
                    pos += binary2hexstr(ptr + 1, e->len - 2, &tbuf[pos], sizeof(tbuf) - pos);
                    if (unlikely(pos >= sizeof(tbuf)))
                        return EDPVS_NOROOM;
                    lldp_dump_snprintf(tbuf, pos, "%c", '\n');
                    break;
            }
            break;
        case LLDP_CHASSIS_ID_INTERFACE_NAME:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tInterface Name: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_CHASSIS_ID_LOCALLY_ASSIGNED:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tLocal: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        default:
            lldp_dump_snprintf(tbuf, pos, "\t%s: ", "Bad Chassis ID");
            pos += binary2print(ptr, e->len - 1, &tbuf[pos], sizeof(tbuf) - pos);
            if (unlikely(pos >= sizeof(tbuf)))
                return EDPVS_NOROOM;
            lldp_dump_snprintf(tbuf, pos, "%c", '\n');
            break;
    }

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }
    return pos;
}

static int lldp_parse_type_port_id(const char *lldpdu, lldp_type_t *type, uint16_t *len)
{
    assert(type != NULL);

    type->type = DPVS_LLDP_TL_TYPE((uint16_t)(*lldpdu));
    if (!LLDP_TYPE_VALID(type->type)) {
        type->type = 0;
        return EDPVS_INVAL;
    }

    type->subtype = *(lldpdu + 2);
    if (!LLDP_PORT_ID_VALID(type->subtype)) {
        type->subtype = 0;
        return EDPVS_INVAL;
    }

    if (len)
        *len = DPVS_LLDP_TL_LEN(*((uint16_t *)lldpdu));

    return EDPVS_OK;
}

static int lldp_local_pdu_port_id(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    size_t datalen = strlen(dev->name);

    assert(datalen < IFNAMSIZ);

    if (len >= 2 + 1 + datalen) {
        *((uint16_t *)buf) = DPVS_LLDP_TL(LLDP_TYPE_PORT_ID, 1 + datalen);
        buf[2]  = LLDP_PORT_ID_INTERFACE_NAME;
        rte_memcpy(&buf[3], &dev->name, datalen);
    } else {
        memset(buf, 0, len);
    }

    return 2 + 1 + datalen;
}

static int lldp_dump_port_id(const struct lldp_entry *e, char *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)e->value;    /* Port ID Subtype */
    int pos = 0;
    char tbuf[512], ipbuf[64];

    lldp_dump_snprintf(tbuf, pos, "%s (%d)\n", "Port ID TLV", e->type.type);
    assert(e->type.subtype == *ptr);

    ++ptr;                                              /* Port ID Data */
    switch (e->type.subtype) {
        case LLDP_PORT_ID_INTERFACE_ALIAS:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tInterface Alias: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_PORT_ID_PORT_COMPONENT:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tPort Component: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_PORT_ID_MAC_ADDRESS:
            if (unlikely(e->len < 7))
                return EDPVS_INVPKT;
            lldp_dump_snprintf(tbuf, pos, "\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
            break;
        case LLDP_PORT_ID_NETWORK_ADDRESS:
            switch (*ptr) {
                case LLDP_ADDR_IPV4:
                    if (unlikely(e->len < 6))
                        return EDPVS_INVPKT;
                    lldp_dump_snprintf(tbuf, pos, "\tIPv4: %s\n", inet_ntop(AF_INET, ptr + 1,
                                ipbuf, sizeof(ipbuf)) ?: "Unknown");
                    break;
                case LLDP_ADDR_IPV6:
                    if (unlikely(e->len < 18))
                        return EDPVS_INVPKT;
                    lldp_dump_snprintf(tbuf, pos, "\tIPv6: %s\n", inet_ntop(AF_INET6, ptr + 1,
                                ipbuf, sizeof(ipbuf)) ?: "Unknown");
                    break;
                default:
                    if (unlikely(e->len <= 2))
                        return EDPVS_INVPKT;
                    lldp_dump_snprintf(tbuf, pos, "\tNetwork Address Type %d:", *ptr);
                    pos += binary2hexstr(ptr + 1, e->len - 2, &tbuf[pos], sizeof(tbuf) - pos);
                    if (unlikely(pos >= sizeof(tbuf)))
                        return EDPVS_NOROOM;
                    lldp_dump_snprintf(tbuf, pos, "%c", '\n');
                    break;
            }
            break;
        case LLDP_PORT_ID_INTERFACE_NAME:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tInterface Name: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len - 1, "\n");
            break;
        case LLDP_PORT_ID_AGENT_CIRCUIT_ID:
            lldp_dump_snprintf(tbuf, pos, "\t%s: ", "Agent Circuit ID");
            pos += binary2hexstr(ptr, e->len - 1, &tbuf[pos], sizeof(tbuf) - pos);
            if (unlikely(pos >= sizeof(tbuf)))
                return EDPVS_NOROOM;
            lldp_dump_snprintf(tbuf, pos, "%c", '\n');
            break;
        case LLDP_PORT_ID_LOCALLY_ASSIGNED:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tLocal: ");
            lldp_dump_strcpy(tbuf, pos, ptr, e->len -1, "\n");
            break;
        default:
            lldp_dump_snprintf(tbuf, pos, "\t%s: ", "Bad Port ID");
            pos += binary2print(ptr, e->len - 1, &tbuf[pos], sizeof(tbuf) - pos);
            if (unlikely(pos >= sizeof(tbuf)))
                return EDPVS_NOROOM;
            lldp_dump_snprintf(tbuf, pos, "%c", '\n');
            break;
    }

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }
    return pos;
}

static int lldp_local_pdu_ttl(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    uint16_t *data;

    if (len >=  4) {
        data = (uint16_t *)buf;
        *data++ = DPVS_LLDP_TL(LLDP_TYPE_TTL, 2);
        *data = rte_cpu_to_be_16(DPVS_LLDP_TTL_DEFAULT);
    } else {
        memset(buf, 0, len);
    }

    return 4;
}

static int lldp_dump_ttl(const struct lldp_entry *e, char *buf, size_t len)
{
    uint16_t *ttl = (uint16_t *)e->value;
    return snprintf(buf, len, "Time to Live TLV (%d)\n\t%d\n", e->type.type, rte_be_to_cpu_16(*ttl));
}

static int lldp_on_change_ttl(const struct lldp_entry *e)
{
    struct lldp_port *port = e->port;
    uint16_t ttl;
    const void *ptr;

    /* Lifespan of local lldp caches is not decided by ttl. Actually, they are
     * updated periodically in every DPVS_LLDP_UPDATE_INTERVAL second. If not updated
     * in 3 * DPVS_LLDP_UPDATE_INTERVAL seconds, they are expired and removed.
     * */
    if (port->neigh == DPVS_LLDP_NODE_LOCAL)
        return EDPVS_OK;

    ptr = &e->value[0];
    ttl = rte_be_to_cpu_16(*((uint16_t *)ptr));
    if (ttl != port->timeout) {
        RTE_LOG(INFO, LLDP, "%s: update neigh lldp ttl %u -> %u\n", __func__, port->timeout, ttl);
        port->timeout = ttl;
    }

    return EDPVS_OK;
}

static int lldp_local_pdu_port_desc(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    size_t desc_len;
    char desc[128];

    desc_len = snprintf(desc, sizeof(desc), "DPVS Server Port: Interface %s, Index %d, Kni %s",
            dev->name, dev->id, dev->kni.kni ? dev->kni.name : "None");
    if (2 + desc_len <= len) {
        *((uint16_t *)buf) = DPVS_LLDP_TL(LLDP_TYPE_PORT_DESC, desc_len);
        rte_memcpy(&buf[2], desc, desc_len);
    } else {
        memset(buf, 0, len);
    }

    return 2 + desc_len;
}

static int lldp_dump_port_desc(const struct lldp_entry *e, char *buf, size_t len)
{
    int pos = 0;
    char tbuf[1024];

    lldp_dump_snprintf(tbuf, pos, "Port Description TLV (%d)\n\t", e->type.type);
    if (likely(e->len > 0))
        lldp_dump_strcpy(tbuf, pos, e->value, e->len, "\n");

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }

    return pos;
}

static int lldp_local_pdu_sys_name(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    size_t host_len;
    char hostname[HOST_NAME_MAX + 1];

    if (unlikely(gethostname(hostname, sizeof(hostname)) != 0))
        snprintf(hostname, sizeof(hostname), "%s", "Unknown");

    host_len = strlen(hostname);
    if (2 + host_len <= len) {
        *((uint16_t *)buf) = DPVS_LLDP_TL(LLDP_TYPE_SYS_NAME, host_len);
        rte_memcpy(&buf[2], hostname, host_len);
    } else {
        memset(buf, 0, len);
    }

    return 2 + host_len;
}

static int lldp_dump_sys_name(const struct lldp_entry *e, char *buf, size_t len)
{
    int pos = 0;
    char tbuf[1024];

    lldp_dump_snprintf(tbuf, pos, "System Name TLV (%d)\n\t", e->type.type);
    if (likely(e->len > 0))
        lldp_dump_strcpy(tbuf, pos, e->value, e->len, "\n");

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }

    return pos;
}

static int lldp_local_pdu_sys_desc(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    int rc;

    rc = snprintf(buf + 2, len - 2, "%s %s %s %s %s, Serail Number %s",
            lldp_uname.sysname, lldp_uname.nodename, lldp_uname.release,
            lldp_uname.version, lldp_uname.machine, lldp_sn);
    if (unlikely(rc < 0))
        return EDPVS_IO;
    *((uint16_t *)buf) = DPVS_LLDP_TL(LLDP_TYPE_SYS_DESC, rc);

    return rc;
}

static int lldp_dump_sys_desc(const struct lldp_entry *e, char *buf, size_t len)
{
    int pos = 0;
    char tbuf[1024];

    lldp_dump_snprintf(tbuf, pos, "System Description TLV (%d)\n\t", e->type.type);
    if (likely(e->len > 0))
        lldp_dump_strcpy(tbuf, pos, e->value, e->len, "\n");

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }
    return pos;
}

static const char *lldp_bit2sys_cap(uint16_t capacities, uint8_t bitpos)
{
    switch (capacities & (1UL << bitpos)) {
        case 0x0001:
            return "Other";
        case 0x0002:
            return "Repeater";
        case 0x0004:
            return "Bridge";
        case 0x0008:
            return "WLAN Access Point";
        case 0x0010:
            return "Router";
        case 0x0020:
            return "Telephone";
        case 0x0040:
            return "DOCSIS cable device";
        case 0x0080:
            return "Station Only";
        case 0x0100:
            return "Client";
        case 0x0200:
            return "ISDN Terminal Adapter";
        case 0x0400:
            return "Cryptographic Device";
        case 0x0800:
            return "Voice Gateway";
        case 0x1000:
            return "LAN Endpoint";
        case 0x2000:
        case 0x4000:
        case 0x8000:
            return "Reserved";
        default:
            return "";
    }
    return "";
}

static int lldp_local_pdu_sys_cap(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    if (len >= 2 + 4) {
        *((uint16_t *)&buf[0]) = DPVS_LLDP_TL(LLDP_TYPE_SYS_CAP, 4);
        *((uint16_t *)&buf[2]) = rte_cpu_to_be_16(0x80);    /* Capacity: Station Only */
        *((uint16_t *)&buf[4]) = rte_cpu_to_be_16(0x80);    /* Enabled:  Station Only */
    }

    return 2 + 4;
}

static int lldp_dump_sys_cap(const struct lldp_entry *e, char *buf, size_t len)
{
    uint8_t i, first;
    uint16_t capacities, enables;
    int pos = 0;
    char tbuf[256];
    const void *ptr;

    if (e->len != 4)
        return EDPVS_INVPKT;
    ptr = &e->value[0];
    capacities = rte_be_to_cpu_16(*((uint16_t *)ptr));
    ptr = &e->value[2];
    enables = rte_be_to_cpu_16(*((uint16_t *)ptr));

    lldp_dump_snprintf(tbuf, pos, "System Capabilities TLV (%d)\n", e->type.type);

    first = 1;
    for (i = 0; i < 16; i++) {
        if (!(capacities & (1UL << i)))
            continue;
        if (first) {
            lldp_dump_snprintf(tbuf, pos, "\tSystem capabilities: %s",
                    lldp_bit2sys_cap(capacities, i));
            first = 0;
        } else {
            lldp_dump_snprintf(tbuf, pos, ", %s", lldp_bit2sys_cap(capacities, i));
        }
    }
    lldp_dump_snprintf(tbuf, pos, "%c", '\n');

    first = 1;
    for (i = 0; i < 16; i++) {
        if (!(enables & (1UL << i)))
            continue;
        if (first) {
            lldp_dump_snprintf(tbuf, pos, "\tEnabled capabilities: %s",
                    lldp_bit2sys_cap(enables, i));
            first = 0;
        } else {
            lldp_dump_snprintf(tbuf, pos, ", %s", lldp_bit2sys_cap(enables, i));
        }
    }
    lldp_dump_snprintf(tbuf, pos, "%c", '\n');

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 11] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }
    return pos;
}

static int lldp_parse_type_mng_addr(const char *lldpdu, lldp_type_t *type, uint16_t *len)
{
    assert(NULL != type);

    type->type = DPVS_LLDP_TL_TYPE((uint16_t)(*lldpdu));
    if (!LLDP_TYPE_VALID(type->type)) {
        type->type = 0;
        return EDPVS_INVAL;
    }
    type->subtype = *((uint8_t *)(lldpdu + 3));

    if (len)
        *len = DPVS_LLDP_TL_LEN(*((uint16_t *)lldpdu));

    return EDPVS_OK;
}

static int lldp_local_pdu_mng_addr(const struct netif_port *dev, uint32_t subtype, char *buf, size_t len)
{
    int rc;
    uint8_t tbuf[512];
    uint8_t *ptr;
    struct sockaddr_storage addr;
    char ifname[IFNAMSIZ];
    uint16_t typlen;

    ptr = tbuf + 2;
    *(ptr + 1) = subtype;
    switch (subtype) {
        case LLDP_ADDR_ALL802:
            *ptr = 7;
            rte_memcpy(ptr + 2, &dev->addr, 6);
            ptr += 8;
            break;
        case LLDP_ADDR_IPV4:
            *ptr = 5;
            rc = get_host_addr(dev->kni.kni ? dev->kni.name : NULL, &addr, NULL, ifname, NULL);
            if (rc < 0)
                return rc;
            if (rc & 0x1)
                rte_memcpy(ptr + 2, &((struct sockaddr_in *)&addr)->sin_addr.s_addr, 4);
            else
                ifname[0] = '\0';
            ptr += 6;
            break;
        case LLDP_ADDR_IPV6:
            *ptr = 17;
            rc = get_host_addr(dev->kni.kni ? dev->kni.name : NULL, NULL, &addr, NULL, ifname);
            if (rc < 0)
                return rc;
            if (rc &0x2)
                rte_memcpy(ptr + 2, &((struct sockaddr_in6 *)&addr)->sin6_addr, 16);
            else
                ifname[0] = '\0';
            ptr += 18;
            break;
        default:
            return EDPVS_NOTSUPP;
    }

    if (subtype == LLDP_ADDR_ALL802) {
        *ptr++ = 2;       /* Interface Subtype: Ifindex */
        *((uint32_t *)ptr) = rte_cpu_to_be_32(dev->id);
    } else if (ifname[0]) {
        *ptr++ = 2;       /* Interface Subtype: Ifindex */
        rc = linux_ifname2index(ifname);
        if (rc < 0)
            return EDPVS_SYSCALL;
        *((uint32_t *)ptr) = rte_cpu_to_be_32(rc);
    } else {
        *ptr++ = 1;      /* Interface Subtype: Unknown */
        *((uint32_t *)ptr) = 0;
    }

    ptr += 4;           /* OID String Length */
    *ptr++ = 0;

    typlen = DPVS_LLDP_TL(LLDP_TYPE_MNG_ADDR, ptr - tbuf - 2);
    rte_memcpy(tbuf, &typlen, 2);

    if (ptr - tbuf > len)
        rte_memcpy(buf, tbuf, len);
    else
        rte_memcpy(buf, tbuf, ptr - tbuf);
    return ptr - tbuf;
}

static int lldp_dump_mng_addr(const struct lldp_entry *e, char *buf, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)e->value; /* Address Length */
    uint8_t addrlen, intf_subtype, oidlen;
    int pos = 0;
    char tbuf[1024], ipbuf[64];

    lldp_dump_snprintf(tbuf, pos, "%s (%d)\n", "Management Address TLV", e->type.type);
    addrlen = *ptr;
    ++ptr;      /* Address Subtype */
    assert(e->type.subtype == *ptr);

    ++ptr;      /* Management Address */
    switch (e->type.subtype) {
        case LLDP_ADDR_ALL802:
            if (unlikely(addrlen < 7))
                return EDPVS_INVPKT;
            lldp_dump_snprintf(tbuf, pos, "\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
            break;
        case LLDP_ADDR_IPV4:
            if (unlikely(addrlen < 5))
                return EDPVS_INVPKT;
            lldp_dump_snprintf(tbuf, pos, "\tIPv4: %s\n",
                    inet_ntop(AF_INET, ptr, ipbuf, sizeof(ipbuf)) ?: "Unknown");
            break;
        case LLDP_ADDR_IPV6:
            if (unlikely(addrlen < 17))
                return EDPVS_INVPKT;
            lldp_dump_snprintf(tbuf, pos, "\tIPv6: %s\n",
                    inet_ntop(AF_INET6, ptr, ipbuf, sizeof(ipbuf)) ?: "Unknown");
            break;
        default:
            lldp_dump_snprintf(tbuf, pos, "\tNetwork Address Type(%d): ", e->type.subtype);
            pos += binary2hexstr(ptr, addrlen - 1, &tbuf[pos], sizeof(tbuf) - pos);
            if (unlikely(pos >= sizeof(tbuf)))
                return EDPVS_NOROOM;
            lldp_dump_snprintf(tbuf, pos, "%c", '\n');
            break;
    }

    ptr = ptr + addrlen - 1; /* Interface Subtype */
    intf_subtype = *ptr;
    switch (intf_subtype) {
        case 1:
            lldp_dump_snprintf(tbuf, pos, "\tUnknown interface subtype(%d): ", intf_subtype);
            break;
        case 2:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tIfindex: ");
            break;
        case 3:
            lldp_dump_snprintf(tbuf, pos, "%s", "\tSystem port number: ");
            break;
        default:
            lldp_dump_snprintf(tbuf, pos, "\tUnsupported interface subtype(%d): ", intf_subtype);
            break;
    }
    ++ptr;      /* Interface */
    lldp_dump_snprintf(tbuf, pos, "%d\n", rte_be_to_cpu_32(*((uint32_t *)ptr)));

    ptr += 4;   /* OID String Length */
    oidlen = *ptr;

    ++ptr;      /* OID String */
    if (oidlen > 128)
        lldp_dump_snprintf(tbuf, pos, "\tOID: Invalid length = %d\n", oidlen);
    else if (oidlen > 0) {
        lldp_dump_snprintf(tbuf, pos, "%s", "\tOID: ");
        pos += binary2hexstr((const uint8_t *)ptr, oidlen, &tbuf[pos], sizeof(tbuf) - pos);
        if (pos >= sizeof(tbuf))
            return EDPVS_NOROOM;
        lldp_dump_snprintf(tbuf, pos, "%c", '\n');
    }

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }
    return pos;
}

static int lldp_parse_type_org(const char *lldpdu, lldp_type_t *type, uint16_t *len)
{
    assert(type != NULL);

    type->type = DPVS_LLDP_TL_TYPE((uint16_t)(*lldpdu));
    if (!LLDP_TYPE_VALID(type->type)) {
        type->type = 0;
        return EDPVS_INVAL;
    }

    /* subtype := ((24-bit Orgnization Unique Code) << 8) | (8-bit Subtype) */
    type->subtype = rte_be_to_cpu_32(*((uint32_t *)&lldpdu[2]));

    if (len)
        *len = DPVS_LLDP_TL_LEN(*((uint16_t *)lldpdu));

    return EDPVS_OK;
}

static int lldp_dump_org_specific(const struct lldp_entry *e, char *buf, size_t len)
{
    // TODO: Implement Organizationally Specific TLVs

    const unsigned char *ptr = (unsigned char *)e->value;
    int pos = 0;
    char tbuf[1024];

    if (e->len < 4)
        return EDPVS_INVPKT;

    lldp_dump_snprintf(tbuf, pos, "Organizationally Specific TLV (%d): Code %02x:%02x:%02x, "
            "Subtype %02d\n\t", e->type.type, ptr[0], ptr[1], ptr[2], ptr[3]);
    pos += binary2hexstr((const uint8_t *)(&ptr[4]), e->len - 4, &tbuf[pos], sizeof(tbuf) - pos);
    if (pos >= sizeof(tbuf))
        return EDPVS_NOROOM;
    lldp_dump_snprintf(tbuf, pos, "%c", '\n');

    if (pos >= len) {
        rte_memcpy(buf, tbuf, len - 1);
        buf[len - 1] = '\0';
    } else {
        rte_memcpy(buf, tbuf, pos);
        buf[pos] = '\0';
    }
    return pos;
}

static struct lldp_port *lldp_port_get(portid_t pid, uint16_t neigh)
{
    struct lldp_port *lp;

    if (unlikely(neigh >= DPVS_LLDP_NODE_MAX))
        return NULL;

    list_for_each_entry(lp, &lldp_ports[neigh], node) {
        if (lp->dev->id == pid) {
            assert(lp->neigh == neigh);
            return lp;
        }
    }
    return NULL;
}

static void lldp_port_hash(struct lldp_port *port)
{
    struct lldp_port *entry, *next = NULL;

    assert(port->neigh < DPVS_LLDP_NODE_MAX);

    list_for_each_entry(entry, &lldp_ports[port->neigh], node) {
        if (entry->dev->id >= port->dev->id) {
            next = entry;
            break;
        }
    }

    if (NULL != next)
        list_add_tail(&port->node, &next->node);
    else
        list_add_tail(&port->node, &lldp_ports[port->neigh]);
}

static inline void lldp_port_unhash(struct lldp_port *port)
{
    list_del_init(&port->node);
}

static int lldp_entry_del(struct lldp_entry *entry);
static int lldp_port_del(struct lldp_port *port, bool in_timer)
{
    int err;
    struct lldp_entry *entry, *next;

    lldp_port_unhash(port);

    list_for_each_entry_safe(entry, next, &port->head, node) {
        err = lldp_entry_del(entry);
        if (err != EDPVS_OK)
            RTE_LOG(WARNING, LLDP, "%s: fail to del lldp %s entry, port %s type %d:%d error %s\n",
                    __func__, port->neigh ? "neigh" : "local", port->dev->name,
                    entry->type.type, entry->type.subtype, dpvs_strerror(err));
    }
    assert(port->entries == 0);

    if (in_timer)
        err = dpvs_timer_cancel_nolock(&port->timer, true);
    else
        err = dpvs_timer_cancel(&port->timer, true);
    if (err != EDPVS_OK)
        RTE_LOG(WARNING, LLDP, "%s: fail to cancel lldp port timer, port %s error %s\n",
                __func__, port->dev->name, dpvs_strerror(err));

    rte_free(port);
    return EDPVS_OK;
}

static int lldp_port_timeout(void *arg)
{
    struct lldp_port *port = arg;

    RTE_LOG(DEBUG, LLDP,"%s: %s lldp cache on %s expired\n", __func__,
            port->neigh == DPVS_LLDP_NODE_LOCAL ? "local" : "neighbor",
            port->dev->name);

    lldp_port_del(port, true);
    return DTIMER_STOP;
}

static int lldp_port_add(struct netif_port *dev, uint16_t neigh, uint16_t timeout, bool in_timer)
{
    int err;
    struct lldp_port *lp;
    struct timeval to = { .tv_sec = timeout };

    if (neigh >= DPVS_LLDP_NODE_MAX)
        return EDPVS_INVAL;

    if (lldp_port_get(dev->id, neigh))
        return EDPVS_EXIST;

    lp = rte_zmalloc("lldp_port", sizeof(*lp), RTE_CACHE_LINE_SIZE);
    if (unlikely(!lp))
        return EDPVS_NOMEM;

    lp->dev     = dev;
    lp->neigh   = neigh;
    lp->timeout = timeout ?: DPVS_LLDP_TTL_DEFAULT;
    INIT_LIST_HEAD(&lp->head);

    lldp_port_hash(lp);

    dpvs_time_rand_delay(&to, 1000000);
    if (in_timer)
        err = dpvs_timer_sched_nolock(&lp->timer, &to, lldp_port_timeout, lp, true);
    else
        err = dpvs_timer_sched(&lp->timer, &to, lldp_port_timeout, lp, true);
    if (err != EDPVS_OK) {
        lldp_port_unhash(lp);
        rte_free(lp);
        return err;
    }

    return EDPVS_OK;
}

static struct lldp_entry *lldp_entry_get(const struct lldp_port *port, lldp_type_t type)
{
    struct lldp_entry *e;

    if (unlikely(NULL == port))
        return NULL;

    list_for_each_entry(e, &port->head, node) {
        if (lldp_type_equal(e->type, type))
            return e;
    }
    return NULL;
}

static void lldp_entry_hash(struct lldp_entry *e, struct lldp_port *port)
{
    struct lldp_entry *entry, *next = NULL;

    /* put LLDP_TYPE_END node at tail */
    if (unlikely(!e->type.type)) {
        list_add_tail(&e->node, &port->head);
        ++port->entries;
        return;
    }

    list_for_each_entry(entry, &port->head, node) {
        if (!entry->type.type || lldp_type_cmp(&entry->type, &e->type) >= 0) {
            next = entry;
            break;
        }
    }

    if (NULL != next)
        list_add_tail(&e->node, &next->node);
    else
        list_add_tail(&e->node, &port->head);
    ++port->entries;
}

static inline void lldp_entry_unhash(struct lldp_entry *e)
{
    list_del_init(&e->node);
    --e->port->entries;
}

static int lldp_entry_del(struct lldp_entry *entry)
{
    lldp_entry_unhash(entry);
    rte_free(entry);
    return EDPVS_OK;
}

static int lldp_entry_add(struct lldp_port *port, char *lldpdu)
{
    int err;
    lldp_type_t type;
    uint16_t len;
    struct lldp_entry *entry;
    struct lldp_type_ops *ops;

    type.type = DPVS_LLDP_TL_TYPE((uint16_t)(*lldpdu));
    ops = lldp_type_get(type);
    if (!ops)
        return EDPVS_NOTSUPP;
    err = ops->parse_type(lldpdu, &type, &len);
    if (EDPVS_OK != err)
        return err;
    assert(len <= DPVS_LLDP_PDU_MAX);

    entry = lldp_entry_get(port, type);
    if (entry) {
        /* do update */
        if (entry->len >= len) {
            entry->len = len;
            entry->stale = 0;
            rte_memcpy(&entry->typelen, lldpdu, len + 2);
            if (ops->on_change)
                return ops->on_change(entry);
            return EDPVS_OK;
        }
        lldp_entry_del(entry);
    }

    entry = rte_zmalloc("lldp_entry", sizeof(struct lldp_entry) + len + 2, RTE_CACHE_LINE_SIZE);
    if (unlikely(!entry))
        return EDPVS_NOMEM;
    entry->type = type;
    entry->len  = len;
    entry->port = port;
    rte_memcpy(&entry->typelen, lldpdu, len + 2);

    lldp_entry_hash(entry, port);

    if (ops->on_change)
        return ops->on_change(entry);
    return EDPVS_OK;
}

static int lldp_dump_pdu(const struct lldp_port *port, char *buf, size_t buflen)
{
    int rc;
    size_t room;
    char *ptr;
    struct lldp_entry *e;
    struct lldp_type_ops *ops;

    ptr = buf;
    room = buflen;
    list_for_each_entry(e, &port->head, node) {
        if (room <= 0)
            return EDPVS_NOROOM;
        ops = lldp_type_get(e->type);
        if (unlikely(!ops))
            return EDPVS_NOTSUPP;
        if (ops->dump) {
            rc = ops->dump(e, ptr, room);
            if (unlikely(rc < 0))
                return rc;
            if (unlikely(rc > room))
                return EDPVS_NOROOM;
            ptr += rc;
            room -= rc;
        }
    }

    return EDPVS_OK;
}

static int lldp_pdu_local_update(struct netif_port *dev, bool in_timer)
{
    int i, rc;
    struct lldp_port *port;
    struct lldp_type_ops *ops;
    char buf[DPVS_LLDP_PDU_MAX];

    static lldp_type_t local_lldp_types[] = {
        { LLDP_TYPE_CHASSIS_ID, LLDP_CHASSIS_ID_MAC_ADDRESS },
        { LLDP_TYPE_PORT_ID, LLDP_PORT_ID_INTERFACE_NAME },
        { LLDP_TYPE_TTL, 0 },
        { LLDP_TYPE_PORT_DESC, 0 },
        { LLDP_TYPE_SYS_NAME, 0 },
        { LLDP_TYPE_SYS_DESC, 0 },
        { LLDP_TYPE_SYS_CAP, 0 },
        { LLDP_TYPE_MNG_ADDR, 1 },  /* ipv4 */
        { LLDP_TYPE_MNG_ADDR, 2 },  /* ipv6 */
        { LLDP_TYPE_END, 0 },
    };

    port = lldp_port_get(dev->id, DPVS_LLDP_NODE_LOCAL);
    if (!port) {
        /* timeout of 3*DPVS_LLDP_UPDATE_INTERVA ensures local lldp caches persist */
        rc = lldp_port_add(dev, DPVS_LLDP_NODE_LOCAL, 3 * DPVS_LLDP_UPDATE_INTERVAL, in_timer);
        if (unlikely(EDPVS_OK != rc))
            return rc;
        port = lldp_port_get(dev->id, DPVS_LLDP_NODE_LOCAL);
        assert(port != NULL);
    }

    for (i = 0; i < NELEMS(local_lldp_types); i++) {
        ops = lldp_type_get(local_lldp_types[i]);
        if (!ops || !ops->local_lldp)
            continue;
        rc = ops->local_lldp(dev, local_lldp_types[i].subtype, buf, sizeof(buf));
        if (unlikely(rc < 0)) {
            RTE_LOG(INFO, LLDP, "%s: fail to generate local lldp pdu, type %d.%d,"
                    " err %s\n", __func__, local_lldp_types[i].type,
                    local_lldp_types[i].subtype, dpvs_strerror(rc));
            continue;
        }
        if (unlikely(rc > sizeof(buf)))
            return EDPVS_NOROOM;
        rc = lldp_entry_add(port, buf);
        if (EDPVS_OK != rc)
            return rc;
    }

    if (in_timer)
        dpvs_timer_reset_nolock(&port->timer, true);
    else
        dpvs_timer_reset(&port->timer, true);

    return EDPVS_OK;
}

static int lldp_pdu_neigh_update(struct netif_port *dev, const struct rte_mbuf *mbuf, bool in_timer)
{
    int err;
    char *ptr;
    size_t totlen;
    uint16_t typelen;
    uint16_t len;
    uint8_t type;
    bool check_stale = false;
    struct lldp_port *port;
    struct lldp_entry *entry, *next;
    struct timeval timeout;

    port = lldp_port_get(dev->id, DPVS_LLDP_NODE_NEIGH);
    if (!port) {
        err = lldp_port_add(dev, DPVS_LLDP_NODE_NEIGH, DPVS_LLDP_TTL_DEFAULT, in_timer);
        if (unlikely(EDPVS_OK != err))
            return err;
        port = lldp_port_get(dev->id, DPVS_LLDP_NODE_NEIGH);
        assert(port != NULL);
    } else {
        check_stale = true;
        list_for_each_entry(entry, &port->head, node)
            entry->stale = 1;
    }

    totlen = mbuf->data_len;
    ptr = rte_pktmbuf_mtod(mbuf, char *);
    while (totlen > 0) {
        typelen = *((uint16_t*)ptr);
        type = DPVS_LLDP_TL_TYPE(typelen);
        len = DPVS_LLDP_TL_LEN(typelen) + 2;
        err = lldp_entry_add(port, ptr);
        if (unlikely(EDPVS_OK != err && EDPVS_NOTSUPP != err))
            return err;
        totlen -= len;
        ptr += len;
        if (LLDP_TYPE_END == type)
            break;
    }

    if (check_stale) {
        list_for_each_entry_safe(entry, next, &port->head, node) {
            if (entry->stale)
                lldp_entry_del(entry);
        }
    }

    timeout.tv_sec = port->timeout;
    dpvs_time_rand_delay(&timeout, 1000000);
    if (in_timer)
       err = dpvs_timer_update_nolock(&port->timer, &timeout, true);
    else
       err = dpvs_timer_update(&port->timer, &timeout, true);
    return err;
}

static int lldp_local_update_all(void *arg)
{
    int err;
    portid_t i, start, end;
    struct netif_port *dev;

    RTE_LOG(DEBUG, LLDP, "%s: updating local lldp cache\n", __func__);

    netif_physical_port_range(&start, &end);
    for (i = start; i < end; i++) {
        dev = netif_port_get(i);
        assert(dev != NULL);
        if (!(dev->flag & NETIF_PORT_FLAG_LLDP))
            continue;
        err = lldp_pdu_local_update(dev, true);
        if (EDPVS_OK != err)
            RTE_LOG(WARNING, LLDP, "%s: fail to update local lldp cache on port %s: %s\n",
                    __func__, dev->name, dpvs_strerror(err));
    }

    return DTIMER_OK;
}

static int lldp_xmit(struct netif_port *dev, bool in_timer)
{
    int err;
    char *ptr;
    struct rte_mbuf *mbuf;
    struct lldp_port *port;
    struct lldp_entry *entry;
    struct rte_ether_hdr *ehdr;

    port = lldp_port_get(dev->id, DPVS_LLDP_NODE_LOCAL);
    if (!port || port->entries <= 0) {
        err = lldp_pdu_local_update(dev, in_timer); // FIXME: update lldp cache asynchronously
        if (EDPVS_OK != err) {
            RTE_LOG(ERR, LLDP, "%s: lldp_pdu_local_update failed: %s\n",
                    __func__, dpvs_strerror(err));
            return err;
        }
        port = lldp_port_get(dev->id, DPVS_LLDP_NODE_LOCAL);
        if (unlikely(!port))
            return EDPVS_NOTEXIST;
        if (port->entries <= 0)
            return EDPVS_OK;
    }

    mbuf = rte_pktmbuf_alloc(dev->mbuf_pool);
    if (unlikely(!mbuf))
        return EDPVS_NOMEM;
    mbuf_userdata_reset(mbuf);

    list_for_each_entry(entry, &port->head, node) {
        ptr = rte_pktmbuf_append(mbuf, entry->len + 2);
        if (unlikely(!ptr))
            return EDPVS_NOROOM;
        rte_memcpy(ptr, &entry->typelen, entry->len + 2);
    }

    ehdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(*ehdr));
    if (unlikely(!ptr))
        return EDPVS_NOROOM;
    rte_memcpy(&ehdr->d_addr, &LLDP_ETHER_ADDR_DST, sizeof(ehdr->d_addr));
    rte_memcpy(&ehdr->s_addr, &dev->addr, sizeof(ehdr->s_addr));
    ehdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP);

    if (dev->type == PORT_TYPE_BOND_SLAVE) {
        // FIXME:
        // How to send LLDP packet on a specified slave port? I found no solutions to it via
        // DPDK API. Maybe changes should be made to bond PMD driver to solve the problem.
        // So I save the slave port id in mbuf, and hope bond PMD driver may consider it when
        // distributing mbufs to slave ports.
        //
        // Store the slave port id into mbuf->port?
        // No! mbuf->port is reset to the bond master's port id in the forthcoming transmit process.
        // Use mbuf->hash.txadapter.reserved2 instead. Hope no conflictions. Remember to reset it to
        // RTE_MBUF_PORT_INVALID in rte_pktmbuf_alloc.
        //
        mbuf->hash.txadapter.reserved2 = dev->id;
        //MBUF_USERDATA(mbuf, portid_t, MBUF_FIELD_ORIGIN_PORT) = port->id;
        dev = dev->bond->slave.master;
    }

    return netif_xmit(mbuf, dev);

}

static int lldp_xmit_all(void *arg)
{
    int err;
    portid_t i, start, end;
    struct netif_port *dev;

    netif_physical_port_range(&start, &end);
    for (i = start; i < end; i++) {
        dev = netif_port_get(i);
        assert(dev != NULL);
        if (!(dev->flag & NETIF_PORT_FLAG_LLDP))
            continue;
        err = lldp_xmit(dev, true);
        if (EDPVS_OK != err)
            RTE_LOG(WARNING, LLDP, "%s: fail to xmit lldp frame on port %s: %s\n",
                    __func__, dev->name, dpvs_strerror(err));
    }

    return DTIMER_OK;
}

static int lldp_ether_addr_filter(bool add)
{
    int err;
    portid_t i, start, end;
    struct netif_port *dev;

    netif_physical_port_range(&start, &end);
    for (i = start; i < end; i++) {
        dev = netif_port_get(i);
        assert(dev != NULL);
        if (add)
            err = netif_mc_add(dev, &LLDP_ETHER_ADDR_DST);
        else
            err = netif_mc_del(dev, &LLDP_ETHER_ADDR_DST);
        if (err != EDPVS_OK)
            return err;
    }

    return EDPVS_OK;
}

static int lldp_xmit_start(void)
{
    int err;
    struct timeval timeout1 = { .tv_sec = DPVS_LLDP_TX_INTERVAL };
    struct timeval timeout2 = { .tv_sec = DPVS_LLDP_UPDATE_INTERVAL };

    assert(rte_lcore_id() == rte_get_main_lcore());

    err = lldp_ether_addr_filter(true);
    if (EDPVS_OK != err && EDPVS_EXIST != err) {
        RTE_LOG(WARNING, LLDP, "%s: failed to add lldp multicast ether address -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    dpvs_time_rand_delay(&timeout1, 1000000);
    err = dpvs_timer_sched_period(&lldp_xmit_timer, &timeout1, lldp_xmit_all, NULL, true);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, LLDP, "%s: failed to schedule lldp_xmit_timer -- %s\n",
                __func__, dpvs_strerror(err));
        lldp_ether_addr_filter(false);
        return err;
    }

    dpvs_time_rand_delay(&timeout2, 1000000);
    err = dpvs_timer_sched_period(&lldp_update_timer, &timeout2, lldp_local_update_all, NULL, true);
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, LLDP, "%s: failed to schedule lldp_update_timer -- %s\n",
                __func__, dpvs_strerror(err));
        dpvs_timer_cancel(&lldp_xmit_timer, true);
        lldp_ether_addr_filter(false);
        return err;
    }

    return EDPVS_OK;
}

static int lldp_xmit_stop(void)
{
    int err;

    assert(rte_lcore_id() == rte_get_main_lcore());

    err = lldp_ether_addr_filter(false);
    if (EDPVS_OK != err && EDPVS_NOTEXIST != err) {
        RTE_LOG(WARNING, LLDP, "%s: failed to del lldp multicast ether address -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    err = dpvs_timer_cancel(&lldp_xmit_timer, true);
    if (EDPVS_OK != err) {
        RTE_LOG(ERR, LLDP, "%s: failed to cancel lldp_xmit_timer -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    err = dpvs_timer_cancel(&lldp_update_timer, true);
    if (EDPVS_OK != err) {
        RTE_LOG(ERR, LLDP, "%s: failed to cancel lldp_update_timer -- %s\n",
                __func__, dpvs_strerror(err));
        return err;
    }

    return EDPVS_OK;
}

static int lldp_rcv(struct rte_mbuf *mbuf, struct netif_port *dev)
{
    int err;
    portid_t pid;
    static uint32_t seq = 0;
    struct dpvs_msg *msg;

    if (!lldp_enable)
        return EDPVS_KNICONTINUE;

    if (is_bond_port(dev->id)) {
        pid = MBUF_USERDATA(mbuf, portid_t, MBUF_FIELD_ORIGIN_PORT);
        dev = netif_port_get(pid);
        if (unlikely(NULL == dev)) {
            RTE_LOG(WARNING, LLDP, "%s: fail to find lldp physical device of port id %d\n",
                    __func__, pid);
            rte_pktmbuf_free(mbuf);
            return EDPVS_RESOURCE;
        }
    }
    if (!(dev->flag & NETIF_PORT_FLAG_LLDP))
        return EDPVS_KNICONTINUE;

    /* redirect lldp mbuf to master lcore */
    msg = msg_make(MSG_TYPE_LLDP_RECV, seq++, DPVS_MSG_UNICAST,
            rte_lcore_id(), sizeof(void *), &mbuf);
    if (unlikely(NULL == msg)) {
        rte_pktmbuf_free(mbuf);
        return EDPVS_NOMEM;
    }

    err = msg_send(msg, rte_get_main_lcore(), DPVS_MSG_F_ASYNC, NULL);
    if (unlikely(EDPVS_OK != err)) {
        RTE_LOG(WARNING, LLDP, "%s: fail to send mbuf to master lcore!\n", __func__);
        rte_pktmbuf_free(mbuf);
    }
    msg_destroy(&msg);
    return err;
}

static int lldp_rcv_msg_cb(struct dpvs_msg *msg)
{
    int err;
    portid_t pid, start, end;
    struct netif_port *dev;
    struct rte_mbuf *mbuf;
    void *msgdata = msg->data;

    mbuf = *(struct rte_mbuf **)msgdata;

    pid = mbuf->port;
    netif_bond_port_range(&start, &end);
    if (pid < end && pid >= start)
        pid = MBUF_USERDATA(mbuf, portid_t, MBUF_FIELD_ORIGIN_PORT);

    dev = netif_port_get(pid);
    if (unlikely(NULL == dev)) {
        RTE_LOG(WARNING, LLDP, "%s: fail to find lldp physical device of port id %d\n",
                __func__, pid);
        rte_pktmbuf_free(mbuf);
        return EDPVS_RESOURCE;
    }

    err = lldp_pdu_neigh_update(dev, mbuf, false);
    rte_pktmbuf_free(mbuf);     /* always consume the mbuf */
    return err;
}

static int lldp_rcv_msg_register(void)
{
    lcoreid_t master_cid = rte_get_main_lcore();
    struct dpvs_msg_type mt = {
        .type = MSG_TYPE_LLDP_RECV,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .cid  = master_cid,
        .unicast_msg_cb = lldp_rcv_msg_cb,
    };

    return msg_type_register(&mt);
}

static int lldp_rcv_msg_unregister(void)
{
    lcoreid_t master_cid = rte_get_main_lcore();
    struct dpvs_msg_type mt = {
        .type = MSG_TYPE_LLDP_RECV,
        .mode = DPVS_MSG_UNICAST,
        .prio = MSG_PRIO_LOW,
        .cid  = master_cid,
        .unicast_msg_cb = lldp_rcv_msg_cb,
    };

    return msg_type_unregister(&mt);
}

static int lldp_sockopt_set(sockoptid_t opt, const void *conf, size_t size)
{
    // TODO
    return EDPVS_NOTSUPP;
}

static int lldp_sockopt_get(sockoptid_t opt, const void *conf, size_t size,
        void **out, size_t *outsize)
{
    const struct lldp_param *param = conf;
    struct lldp_message *message;
    struct netif_port *dev;
    struct lldp_port *port;
    int err;

    *outsize = 0;
    *out = NULL;

    if (!conf || size < sizeof(*param) || !out || !outsize)
        return EDPVS_INVAL;

    if (opt != SOCKOPT_GET_LLDP_SHOW)
        return EDPVS_NOTSUPP;

    dev = netif_port_get_by_name(param->ifname);
    if (!dev) {
        RTE_LOG(WARNING, LLDP, "%s: no such device\n", __func__);
        return EDPVS_NODEV;
    }

    if (param->node >= DPVS_LLDP_NODE_MAX) {
        RTE_LOG(WARNING, LLDP, "%s: invalid node type %d, only supports type "
                "local(%d) and neigh(%d)\n", __func__, param->node,
                DPVS_LLDP_NODE_LOCAL, DPVS_LLDP_NODE_NEIGH);
        return EDPVS_INVAL;
    }

    port = lldp_port_get(dev->id, param->node);
    if (!port) {
        RTE_LOG(INFO, LLDP, "%s: %s lldp port on %s not found!\n", __func__,
                param->node == DPVS_LLDP_NODE_NEIGH ? "neighbor" : "local", dev->name);
        return EDPVS_NOTEXIST;
    }

    message = rte_calloc(NULL, 1, sizeof(*message), 0);
    if (!message)
        return EDPVS_NOMEM;
    rte_memcpy(&message->param, param, sizeof(*param));
    err = lldp_dump_pdu(port, message->message, sizeof(message->message));
    if (EDPVS_OK != err) {
        RTE_LOG(WARNING, LLDP, "%s: lldp_dump_pdu failed -- %s\n",
                __func__, dpvs_strerror(err));
        rte_free(message);
        return err;
    }

    *out = message;
    *outsize = sizeof(*message);
    return EDPVS_OK;
}

static struct dpvs_sockopts lldp_sockopts = {
    .version        = SOCKOPT_VERSION,
    .set_opt_min    = SOCKOPT_SET_LLDP_TODO,
    .set_opt_max    = SOCKOPT_SET_LLDP_TODO,
    .set            = lldp_sockopt_set,
    .get_opt_min    = SOCKOPT_GET_LLDP_SHOW,
    .get_opt_max    = SOCKOPT_GET_LLDP_SHOW,
    .get            = lldp_sockopt_get,
};

static struct lldp_type_ops lldp_ops[] = {
    {
        .type       = LLDP_TYPE_END,
        .parse_type = lldp_parse_type_default,
        .local_lldp = lldp_local_pdu_end,
        .dump       = lldp_dump_end,
    },
    {
        .type       = LLDP_TYPE_CHASSIS_ID,
        .parse_type = lldp_parse_type_chassis_id,
        .local_lldp = lldp_local_pdu_chassis_id,
        .dump       = lldp_dump_chassis_id,
    },
    {
        .type       = LLDP_TYPE_PORT_ID,
        .parse_type = lldp_parse_type_port_id,
        .local_lldp = lldp_local_pdu_port_id,
        .dump       = lldp_dump_port_id,
    },
    {
        .type       = LLDP_TYPE_TTL,
        .parse_type = lldp_parse_type_default,
        .local_lldp = lldp_local_pdu_ttl,
        .dump       = lldp_dump_ttl,
        .on_change  = lldp_on_change_ttl,
    },
    {
        .type       = LLDP_TYPE_PORT_DESC,
        .parse_type = lldp_parse_type_default,
        .local_lldp = lldp_local_pdu_port_desc,
        .dump       = lldp_dump_port_desc,
    },
    {
        .type       = LLDP_TYPE_SYS_NAME,
        .parse_type = lldp_parse_type_default,
        .local_lldp = lldp_local_pdu_sys_name,
        .dump       = lldp_dump_sys_name,
    },
    {
        .type       = LLDP_TYPE_SYS_DESC,
        .parse_type = lldp_parse_type_default,
        .local_lldp = lldp_local_pdu_sys_desc,
        .dump       = lldp_dump_sys_desc,
    },
    {
        .type       = LLDP_TYPE_SYS_CAP,
        .parse_type = lldp_parse_type_default,
        .local_lldp = lldp_local_pdu_sys_cap,
        .dump       = lldp_dump_sys_cap,
    },
    {
        .type       = LLDP_TYPE_MNG_ADDR,
        .parse_type = lldp_parse_type_mng_addr,
        .local_lldp = lldp_local_pdu_mng_addr,
        .dump       = lldp_dump_mng_addr,
    },
    {
        .type       = LLDP_TYPE_ORG,
        .parse_type = lldp_parse_type_org,
        .local_lldp = NULL,
        .dump       = lldp_dump_org_specific,
    }
};

static struct pkt_type dpvs_lldp_pkt_type = {
    //.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP),
    .func = lldp_rcv,
    .port = NULL,
};

int dpvs_lldp_init(void)
{
    int i, err;

    lldp_serail_number_init();

    if (unlikely(uname(&lldp_uname) < 0))
        return EDPVS_SYSCALL;

    for (i = 0; i < DPVS_LLDP_NODE_MAX; i++)
        INIT_LIST_HEAD(&lldp_ports[i]);

    for (i = 0; i < NELEMS(lldp_ops); i++) {
        err = lldp_type_register(&lldp_ops[i]);
        assert(EDPVS_OK == err);
    }

    err = lldp_rcv_msg_register();
    if (EDPVS_OK != err)
        goto unreg_lldp_ops;

    err = sockopt_register(&lldp_sockopts);
    if (EDPVS_OK != err)
        goto unreg_msg;

    dpvs_lldp_pkt_type.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP);
    err = netif_register_pkt(&dpvs_lldp_pkt_type);
    if (EDPVS_OK != err)
        goto unreg_sockopt;

    if (lldp_enable) {
        err = lldp_xmit_start();
        if (EDPVS_OK != err)
            goto unreg_pkttype;
    }

    return EDPVS_OK;

unreg_pkttype:
    netif_unregister_pkt(&dpvs_lldp_pkt_type);
unreg_sockopt:
    sockopt_unregister(&lldp_sockopts);
unreg_msg:
    lldp_rcv_msg_unregister();
unreg_lldp_ops:
    for (i = 0; i < NELEMS(lldp_ops); i++)
        lldp_type_unregister(&lldp_ops[i]);
    return err;
}

int dpvs_lldp_term(void)
{
    int i, err;

    if (lldp_enable)
        lldp_xmit_stop();

    dpvs_lldp_pkt_type.type = rte_cpu_to_be_16(RTE_ETHER_TYPE_LLDP);
    err = netif_unregister_pkt(&dpvs_lldp_pkt_type);
    if (EDPVS_OK != err)
        RTE_LOG(WARNING, LLDP, "%s: fail to unregister lldp packet type\n", __func__);

    err = sockopt_unregister(&lldp_sockopts);
    if (EDPVS_OK != err)
        RTE_LOG(WARNING, LLDP, "%s: fail to unregister lldp msg\n", __func__);
    err = lldp_rcv_msg_unregister();
    if (EDPVS_OK != err)
        RTE_LOG(WARNING, LLDP, "%s: fail to unregister lldp msg\n", __func__);

    for (i = 0; i < NELEMS(lldp_ops); i++) {
        err = lldp_type_unregister(&lldp_ops[i]);
        if (EDPVS_OK != err)
            RTE_LOG(WARNING, LLDP, "%s: lldp_type_unregister(%d) failed\n", __func__, i);
    }

    return EDPVS_OK;
}
