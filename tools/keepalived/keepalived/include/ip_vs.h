#ifndef KEEPALIVED_IP_VS_H
#define KEEPALIVED_IP_VS_H

/* #include "config.h" */

/* System includes */
#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>    /* Force inclusion of net/if.h before linux/if.h */
#include <sys/types.h>
#include <netinet/in.h>
/* Prior to Linux 4.2 have to include linux/in.h and linux/in6.h
 * or linux/netlink.h to include linux/netfilter.h */
#include <linux/netfilter.h>    /* For nf_inet_addr */
#include <linux/types.h>

#include "dp_vs.h"

/////////////////////////////////////////////////////////////////////////////////////////
//
//  Part1. headers derived from "linux/ip_vs.h"
//
/////////////////////////////////////////////////////////////////////////////////////////

#define IP_VS_VERSION_CODE              0x010902            /* DPVS v1.9.2 */
#define NVERSION(version)               \
    (version >> 16) & 0xFF,             \
    (version >> 8) & 0xFF,              \
    version & 0xFF

#define IP_VS_SCHEDNAME_MAXLEN          DP_VS_SCHEDNAME_MAXLEN
#define IP_VS_PENAME_MAXLEN             16
#define IP_VS_IFNAME_MAXLEN             16
#define IP_VS_PEDATA_MAXLEN             255

/* IPVS sync daemon states */
#define IP_VS_STATE_NONE                0x0000              /* daemon is stopped */
#define IP_VS_STATE_MASTER              0x0001              /* started as master */
#define IP_VS_STATE_BACKUP              0x0002              /* started as backup */

/* VRRP IPRoute Flags */
#define IPROUTE_DEL                     0
#define IPROUTE_ADD                     1

#define IPADDRESS_DEL                   0
#define IPADDRESS_ADD                   1

/* IPVS command options */
#define IP_VS_BASE_CTL                  (64+1024+64)        /* base */

#define IP_VS_SO_SET_NONE               IP_VS_BASE_CTL      /* just peek */
#define IP_VS_SO_SET_INSERT             (IP_VS_BASE_CTL+1)
#define IP_VS_SO_SET_ADD                (IP_VS_BASE_CTL+2)
#define IP_VS_SO_SET_EDIT               (IP_VS_BASE_CTL+3)
#define IP_VS_SO_SET_DEL                (IP_VS_BASE_CTL+4)
#define IP_VS_SO_SET_FLUSH              (IP_VS_BASE_CTL+5)
#define IP_VS_SO_SET_LIST               (IP_VS_BASE_CTL+6)
#define IP_VS_SO_SET_ADDDEST            (IP_VS_BASE_CTL+7)
#define IP_VS_SO_SET_DELDEST            (IP_VS_BASE_CTL+8)
#define IP_VS_SO_SET_EDITDEST           (IP_VS_BASE_CTL+9)
#define IP_VS_SO_SET_TIMEOUT            (IP_VS_BASE_CTL+10)
#define IP_VS_SO_SET_STARTDAEMON        (IP_VS_BASE_CTL+11)
#define IP_VS_SO_SET_STOPDAEMON         (IP_VS_BASE_CTL+12)
#define IP_VS_SO_SET_RESTORE            (IP_VS_BASE_CTL+13)
#define IP_VS_SO_SET_SAVE               (IP_VS_BASE_CTL+14)
#define IP_VS_SO_SET_ZERO               (IP_VS_BASE_CTL+15)
#define IP_VS_SO_SET_ADDLADDR           (IP_VS_BASE_CTL+16)
#define IP_VS_SO_SET_DELLADDR           (IP_VS_BASE_CTL+17)
#define IP_VS_SO_SET_ADDBLKLST          (IP_VS_BASE_CTL+18)
#define IP_VS_SO_SET_DELBLKLST          (IP_VS_BASE_CTL+19)
#define IP_VS_SO_SET_ADDTUNNEL          (IP_VS_BASE_CTL+20)
#define IP_VS_SO_SET_DELTUNNEL          (IP_VS_BASE_CTL+21)
#define IP_VS_SO_SET_ADDWHTLST          (IP_VS_BASE_CTL+22)
#define IP_VS_SO_SET_DELWHTLST          (IP_VS_BASE_CTL+23)
#define IP_VS_SO_SET_MAX                IP_VS_SO_SET_DELWHTLST

#define IP_VS_SO_GET_VERSION            IP_VS_BASE_CTL
#define IP_VS_SO_GET_INFO               (IP_VS_BASE_CTL+1)
#define IP_VS_SO_GET_SERVICES           (IP_VS_BASE_CTL+2)
#define IP_VS_SO_GET_SERVICE            (IP_VS_BASE_CTL+3)
#define IP_VS_SO_GET_DESTS              (IP_VS_BASE_CTL+4)
#define IP_VS_SO_GET_DEST               (IP_VS_BASE_CTL+5)  /* not used now */
#define IP_VS_SO_GET_TIMEOUT            (IP_VS_BASE_CTL+6)
#define IP_VS_SO_GET_DAEMON             (IP_VS_BASE_CTL+7)
#define IP_VS_SO_GET_LADDRS             (IP_VS_BASE_CTL+8)
#define IP_VS_SO_GET_MAX                IP_VS_SO_GET_LADDRS

/* Tunnel types */
enum {
    IP_VS_CONN_F_TUNNEL_TYPE_IPIP = 0,  /* IPIP */
    IP_VS_CONN_F_TUNNEL_TYPE_GUE,       /* GUE */
    IP_VS_CONN_F_TUNNEL_TYPE_GRE,       /* GRE */
    IP_VS_CONN_F_TUNNEL_TYPE_MAX,
};

/* Tunnel encapsulation flags */
#define IP_VS_TUNNEL_ENCAP_FLAG_NOCSUM  (0)
#define IP_VS_TUNNEL_ENCAP_FLAG_CSUM    (1 << 0)
#define IP_VS_TUNNEL_ENCAP_FLAG_REMCSUM (1 << 1)

/*
 *    The struct ip_vs_service_user and struct ip_vs_dest_user are
 *    used to set IPVS rules through setsockopt.
 */
struct ip_vs_service_user {
    /* virtual service addresses */
    u_int16_t   protocol;
    __be32      __addr_v4;      /* virtual ip address */
    __be16      port;
    u_int32_t   fwmark;         /* firwall mark of service */

    /* virtual service options */
    char        sched_name[IP_VS_SCHEDNAME_MAXLEN];
    unsigned    flags;          /* virtual service flags */
    unsigned    timeout;        /* persistent timeout in sec */
    unsigned    conn_timeout;
    __be32      netmask;        /* persistent netmask */
    unsigned    bps;
    unsigned    limit_proportion;

    char        srange[256];
    char        drange[256];
    char        iifname[IFNAMSIZ];
    char        oifname[IFNAMSIZ];
};

struct ip_vs_dest_user {
    /* destination server address */
    __be32          addr;
    __be16          port;

    /* real server options */
    unsigned int    conn_flags;    /* connection flags */
    int             weight;        /* destination weight */

    /* thresholds for active connections */
    __u32           u_threshold;    /* upper threshold */
    __u32           l_threshold;    /* lower threshold */
};

struct ip_vs_laddr_user {
    __be32                  __addr_v4;
    u_int16_t               af;
    union nf_inet_addr      addr;
    char                    ifname[IFNAMSIZ];
};

struct ip_vs_blklst_user {
    __be32                  __addr_v4;
    u_int16_t               af;
    union nf_inet_addr      addr;
};

struct ip_vs_whtlst_user {
    __be32                  __addr_v4;
    u_int16_t               af;
    union nf_inet_addr      addr;
};

struct ip_vs_tunnel_user {
    char                    ifname[IFNAMSIZ];
    char                    kind[TNLKINDSIZ];
    char                    link[IFNAMSIZ];
    union nf_inet_addr      laddr;
    union nf_inet_addr      raddr;
};

/*
 *    IPVS statistics object (for user space)
 */
struct ip_vs_stats_user {
    __u64       conns;          /* connections scheduled */
    __u64       inpkts;         /* incoming packets */
    __u64       inbytes;        /* incoming bytes */
    __u64       outpkts;        /* outgoing packets */
    __u64       outbytes;       /* outgoing bytes */

    __u32       cps;            /* current connection rate */
    __u32       inpps;          /* current in packet rate */
    __u32       inbps;          /* current in byte rate */
    __u32       outpps;         /* current out packet rate */
    __u32       outbps;         /* current out byte rate */
};

/* The argument to IP_VS_SO_GET_INFO */
struct ip_vs_getinfo {
    /* version number */
    unsigned int        version;

    /* size of connection hash table */
    unsigned int        size;

    /* number of virtual services */
    unsigned int        num_services;
};

/* The argument to IP_VS_SO_GET_SERVICE */
struct ip_vs_service_entry {
    /* which service: user fills in these */
    __u16               protocol;
    __be32              __addr_v4;      /* virtual address */
    __be16              port;
    __u32               fwmark;         /* firwall mark of service */

    /* service options */
    char                sched_name[IP_VS_SCHEDNAME_MAXLEN];
    unsigned int        flags;          /* virtual service flags */
    unsigned int        timeout;        /* persistent timeout */
    unsigned int        conn_timeout;
    __be32              netmask;        /* persistent netmask */

    /* number of real servers */
    unsigned int        num_dests;
    unsigned int        num_laddrs;
    unsigned int        bps;
    unsigned int        limit_proportion;

    /* statistics */
    struct              ip_vs_stats_user stats;

    char                srange[256];
    char                drange[256];
    char                iifname[IFNAMSIZ];
    char                oifname[IFNAMSIZ];
};

struct ip_vs_dest_entry {
    __be32              __addr_v4;      /* destination address */
    __be16              port;
    unsigned int        conn_flags;     /* connection flags */
    int                 weight;         /* destination weight */

    __u32               u_threshold;    /* upper threshold */
    __u32               l_threshold;    /* lower threshold */

    __u32               activeconns;    /* active connections */
    __u32               inactconns;     /* inactive connections */
    __u32               persistconns;   /* persistent connections */

    /* statistics */
    struct              ip_vs_stats_user stats;
};

struct ip_vs_laddr_entry {
    __be32              __addr_v4;      /* local address - internal use only */
    u_int64_t           port_conflict;  /* conflict counts */
    u_int32_t           conn_counts;    /* current connects */
    u_int16_t           af;
    union nf_inet_addr  addr;
};

/* The argument to IP_VS_SO_GET_LADDRS */
struct ip_vs_get_laddrs {
    /* which service: user fills in these */
    u_int16_t           protocol;
    __be32              __addr_v4;      /* virtual address - internal use only */
    __be16              port;
    u_int32_t           fwmark;         /* firwall mark of service */

    /* number of local address*/
    unsigned int        num_laddrs;
    u_int16_t           af;
    union nf_inet_addr  addr;

    /* the real servers */
    struct ip_vs_laddr_entry    entrytable[0];
};

/* The argument to IP_VS_SO_GET_TIMEOUT */
struct ip_vs_timeout_user {
    int     tcp_timeout;
    int     tcp_fin_timeout;
    int     udp_timeout;
};

/////////////////////////////////////////////////////////////////////////////////////////
//
//  Part2. headers derived from "keepalived/include/ip_vs.h"
//
/////////////////////////////////////////////////////////////////////////////////////////

struct ip_vs_service_app {
    struct ip_vs_service_user   user;
    uint16_t                    af;
    union nf_inet_addr          nf_addr;
    char                        pe_name[IP_VS_PENAME_MAXLEN];
};

struct ip_vs_dest_app {
    struct ip_vs_dest_user  user;
    uint16_t                af;
    union nf_inet_addr      nf_addr;
#ifdef _HAVE_IPVS_TUN_TYPE_
    int                     tun_type;
    int                     tun_port;
#ifdef _HAVE_IPVS_TUN_CSUM_
    int                     tun_flags;
#endif
#endif
};

struct ip_vs_service_entry_app {
    struct ip_vs_service_entry  user;
    struct ip_vs_stats_user     stats;
    uint16_t                    af;
    union nf_inet_addr          nf_addr;
    char                        pe_name[IP_VS_PENAME_MAXLEN];

};

struct ip_vs_dest_entry_app {
    struct ip_vs_dest_entry user;
    struct ip_vs_stats_user stats;
    uint16_t                af;
    union nf_inet_addr      nf_addr;
};

struct ip_vs_get_dests_app {
    struct {    // Can we avoid this duplication of definition?
    /* which service: user fills in these */
    __u16               protocol;
    __be32              __addr_v4;      /* virtual address */
    __be16              port;
    __u32               fwmark;         /* firwall mark of service */

    /* number of real servers */
    unsigned int        num_dests;
    char                srange[256];
    char                drange[256];
    char                iifname[IFNAMSIZ];
    char                oifname[IFNAMSIZ];

    /* the real servers */
    struct ip_vs_dest_entry_app entrytable[0];
    }                   user;

    uint16_t            af;
    union nf_inet_addr  nf_addr;
};

/* The argument to IP_VS_SO_GET_SERVICES */
struct ip_vs_get_services_app {
    struct {
    /* number of virtual services */
    unsigned int    num_services;

    /* service table */
    struct ip_vs_service_entry_app entrytable[0];
    }               user;
};

/* Make sure we don't have an inconsistent definition */
#if IP_VS_IFNAME_MAXLEN > IFNAMSIZ
    #error The code assumes that IP_VS_IFNAME_MAXLEN <= IFNAMSIZ
#endif

/* The argument to IP_VS_SO_GET_DAEMON */
struct ip_vs_daemon_kern {
    /* sync daemon state (master/backup) */
    int             state;

    /* multicast interface name */
    char            mcast_ifn[IP_VS_IFNAME_MAXLEN];

    /* SyncID we belong to */
    int             syncid;
};

struct ip_vs_daemon_app {
    /* sync daemon state (master/backup) */
    int                 state;

    /* multicast interface name */
    char                mcast_ifn[IP_VS_IFNAME_MAXLEN];

    /* SyncID we belong to */
    int                 syncid;

#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
    /* UDP Payload Size */
    uint16_t            sync_maxlen;

    /* Multicast Port (base) */
    uint16_t            mcast_port;

    /* Multicast TTL */
    uint8_t             mcast_ttl;

    /* Multicast Address Family */
    uint16_t            mcast_af;

    /* Multicast Address */
    union nf_inet_addr  mcast_group;
#endif
};

#endif    /* KEEPALIVED_IP_VS_H */
