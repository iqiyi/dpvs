#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <assert.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* configurable number of RX/TX ring descriptors */
#define RTE_TEST_RX_DESC_DEFAULT 256
#define RTE_TEST_TX_DESC_DEFAULT 512

#define NB_MBUF 1048575
#define MAX_PKT_BURST 32

#define RX_QUEUES_PER_PORT 8
#define TX_QUEUES_PER_PORT 8

/*RSS random key supplied in section 7.1.1.7.3 of the Intel 82576 datasheet.
  Used as the default key. */
__rte_unused static uint8_t rss_intel_key[40] = {
	0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
	0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
	0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
	0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
	0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
};

static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode        = ETH_MQ_RX_RSS,
        .max_rx_pkt_len = ETHER_MAX_LEN,
        .split_hdr_size = 0,
        .header_split   = 0,
        .hw_ip_checksum = 1,
        .hw_vlan_filter = 0,
        .jumbo_frame    = 0,
        .hw_strip_crc   = 0,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key    = NULL,
            //.rss_key_len= 40,
            .rss_hf     = ETH_RSS_IP,
        },
    },
    .txmode = {
        .mq_mode        = ETH_MQ_TX_NONE,
    },
    .fdir_conf = {
        .mode           = RTE_FDIR_MODE_SIGNATURE,
        .pballoc        = RTE_FDIR_PBALLOC_64K,
        .status         = RTE_FDIR_REPORT_STATUS_ALWAYS,
        .mask           = {
            .vlan_tci_mask       = 0x0,
            .ipv4_mask           = {
                .src_ip          = 0x00000000,
                .dst_ip          = 0xFFFFFFFF,
                //.dst_ip          = 0x00000000,
            },
            .src_port_mask       = 0x0000,
            .dst_port_mask       = 0x100,
            .mac_addr_byte_mask  = 0x00,
            .tunnel_type_mask    = 0,
            .tunnel_id_mask      = 0x0,
        },
        .drop_queue     = 127,
        .flex_conf = {
            .nb_payloads = 0,
            .nb_flexmasks = 0,
	},
    },
};

static inline int 
is_ipv4_pkt_valid(struct ipv4_hdr *iph, uint32_t link_len)
{
        if (link_len < sizeof(struct ipv4_hdr))
                return 0;

    /* TODO: csum */

        if (((iph->version_ihl) >> 4) != 4)
                return 0;

        if ((iph->version_ihl & 0xf) < 5)
                return 0;

        if (rte_cpu_to_be_16(iph->total_length) < sizeof(struct ipv4_hdr))
                return 0;

        return 1;
}

static void dump_ipv4_hdr(const struct ipv4_hdr *iph,
                          uint16_t port, uint16_t queue,
                          const struct udp_hdr *uh) 
{
    char saddr[16], daddr[16];
    uint16_t lcore;

    lcore = rte_lcore_id();

    if (!inet_ntop(AF_INET, &iph->src_addr, saddr, sizeof(saddr)))
        return;
    if (!inet_ntop(AF_INET, &iph->dst_addr, daddr, sizeof(daddr)))
        return;
    if (ntohs(uh->dst_port) < 5000 || ntohs(uh->dst_port) > 5999)
        return;

    fprintf(stderr, "[%u] port %u queue %d ipv4 hl %u tos %u tot %u "
            "id %u ttl %u prot %u src %s dst %s sport %04x %u dport %04x %u\n",
            lcore, port, queue, IPV4_HDR_IHL_MASK & iph->version_ihl, 
            iph->type_of_service, ntohs(iph->total_length), 
            ntohs(iph->packet_id), iph->time_to_live, 
            iph->next_proto_id, saddr, daddr, 
	    uh->src_port, ntohs(uh->src_port), 
	    uh->dst_port, ntohs(uh->dst_port));
    fflush(stdout);
    return;
}

static int ip_rcv(struct rte_mbuf *mbuf, uint16_t port, uint16_t queue)
{
    struct ipv4_hdr *iph;
    assert(mbuf);
    port = port;
    struct udp_hdr *uh;

    iph = rte_pktmbuf_mtod_offset(mbuf, struct ipv4_hdr *, sizeof(struct ether_hdr));
    if (!is_ipv4_pkt_valid(iph, mbuf->pkt_len))
        return -1; 

    uh = rte_pktmbuf_mtod_offset(mbuf, struct udp_hdr *, 
         sizeof(struct ether_hdr) + (IPV4_HDR_IHL_MASK & iph->version_ihl) * sizeof(uint32_t));

    /* just for test */
    dump_ipv4_hdr(iph, mbuf->port, queue, uh);

    /* csum */

    /* eat and free */
    rte_pktmbuf_free(mbuf);
    return 0;
}

__rte_unused static int fdir_filter(uint32_t soft_id, 
        uint32_t src_ip,
        uint32_t dst_ip,
        uint16_t src_port, 
        uint16_t dst_port,
        enum rte_eth_fdir_behavior fdir_behavior,
        uint8_t port,
        uint16_t rx_queue,
        enum rte_filter_op op_code)
{
    struct rte_eth_fdir_filter flt = {0};
    int ret;
#if 1
    flt.soft_id = soft_id;
    flt.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
    flt.input.flow.udp4_flow.ip.dst_ip = dst_ip;
    //flt.input.flow.udp4_flow.ip.src_ip = src_ip;
    flt.input.flow.udp4_flow.dst_port = rte_cpu_to_be_16(dst_port);
    //flt.input.flow.udp4_flow.src_port = rte_cpu_to_be_16(src_port);
    flt.action.behavior = fdir_behavior;
    flt.action.report_status = RTE_ETH_FDIR_REPORT_ID;
    flt.action.rx_queue = rx_queue;
#else
	flt.soft_id = 1;
	flt.action.rx_queue = 2;
	flt.action.behavior = RTE_ETH_FDIR_ACCEPT;
	flt.action.report_status = RTE_ETH_FDIR_REPORT_ID;
	flt.input.flow_type = RTE_ETH_FLOW_NONFRAG_IPV4_UDP;
	flt.input.flow.udp4_flow.dst_port = 0x6e14;
#endif
    rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_DELETE, &flt);
    ret = rte_eth_dev_filter_ctrl(port, RTE_ETH_FILTER_FDIR, op_code, &flt);
    if (ret < 0)
        printf("flow director programming error: (%s)\n", strerror(-ret));
    else
        printf("fdir setting: dst_ip=%d, dst_port=%d, rx-queue=%d\n", 
             dst_ip, dst_port, rx_queue);
    return ret;
}


/* mempool */
struct rte_mempool *dpdr_pktmbuf_pool = NULL;

static void check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
    #define CHECK_INTERVAL 100 /* 100ms */
    #define MAX_CHECK_TIME 250 /* 25s (250 * 100ms) in total */
    uint8_t portid, count, all_ports_up, print_flag = 0;
    struct rte_eth_link link;

    printf("Checking link statuses...\n");
    fflush(stdout);
    for(count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;
        for(portid = 0; portid < port_num; portid++) {
            if((port_mask & (1 << portid)) == 0)
                continue;
             memset(&link, 0, sizeof(link));
             rte_eth_link_get_nowait(portid, &link);
             /* print link status if flag set */
             if(print_flag == 1) {
                 if(link.link_status) {
                     printf("\nPort %d Link Up - speed %u  Mbps - %s",
                         (uint8_t) portid, (unsigned)link.link_speed,
                         (link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
                         ("full-duplex") : ("half-duplex\n"));
                 } else 
                     printf("Port %d Link Down\n", (uint8_t) portid);
                 continue;
             }
             /* clear all_ports_up flag if any link down */
             if (link.link_status == 0) {
                 all_ports_up = 0;
                 break;
             }
        }
        /* after finally printing all link status, get out */
        if (print_flag == 1)
            break;

        if (all_ports_up == 0) {
            printf(".");
            fflush(stdout);
        }

        /* set the print_flag if all ports up or timeout */
        if (all_ports_up == 1 || count == (MAX_CHECK_TIME -1))
            print_flag = 1;
	rte_delay_ms(100);
    }
    printf("\n");
    fflush(stdout);
}

static int main_loop(__attribute__((unused)) void *dummy)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    unsigned nb_rx, nb_ports;
    unsigned i, k;
    unsigned lcore_id, queue_id;
    __rte_unused unsigned rx_used_desc;
    __rte_unused uint32_t tick = 0;

    nb_ports = 1; //rte_eth_dev_count();
    lcore_id = rte_lcore_id();
    queue_id = lcore_id - 1;

    printf("[lcore_id=%d], port %d, rxq %d\n", lcore_id, 0, queue_id);

    while(1) {
        for(i = 0; i < nb_ports; i++) {
            nb_rx = rte_eth_rx_burst(i, queue_id, pkts_burst, MAX_PKT_BURST);
#if 0
            if(nb_rx) {
                printf("[%d] %d pkts recvd on rxq %u port %d queue"
                    " %d\n", lcore_id, nb_rx, lcore_id, i, queue_id);
            }
#endif
            for(k = 0; k < nb_rx; k++)
                ip_rcv(pkts_burst[i], 0, queue_id);
        }
    }
    return 0;
}

/*
 * usage: ./build/dpdk-test -l 0-8
 * test cmd: echo “test” | socat - udp-connect:224.0.0.24:5230
 */
int main(int argc, char **argv)
{
    int ret, err;
    uint8_t rx_queue_id, tx_queue_id;
    int nb_ports;
    unsigned lcore_id;

    /* init EAL */
    ret = rte_eal_init(argc, argv);
    if(ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    /* create the mbuf pool */
    dpdr_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF, 512,
            0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
    if(dpdr_pktmbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Invalid DPDR arguments\n");

    /* get DPDK ports*/
    nb_ports = rte_eth_dev_count();
    if(nb_ports == 0)
        rte_exit(EXIT_FAILURE, "No Ehernet ports\n");
    if(nb_ports > RTE_MAX_ETHPORTS)
        nb_ports = RTE_MAX_ETHPORTS;

    /* configure device*/
    rte_eth_dev_configure(0, RX_QUEUES_PER_PORT, TX_QUEUES_PER_PORT, &port_conf); 
    if(ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d,"
           " port=%u\n", ret, 0);

    /* init RX queue */
    fflush(stdout);
    for(rx_queue_id = 0; rx_queue_id < RX_QUEUES_PER_PORT; rx_queue_id++){
        ret = rte_eth_rx_queue_setup(0, rx_queue_id, nb_rxd, 
                0 /*rte_eth_dev_socket_id(0)*/, NULL, dpdr_pktmbuf_pool);
        if(ret < 0){
            rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port"
                "=%u, queue_id=%u\n", ret, 0, rx_queue_id);
        }
    }
        
    /* init TX queue */
    fflush(stdout);
    for(tx_queue_id = 0; tx_queue_id < TX_QUEUES_PER_PORT; tx_queue_id++){
        ret = rte_eth_tx_queue_setup(0, tx_queue_id, nb_txd, 
            0 /*rte_eth_dev_socket_id(0)*/, NULL);
        if(ret < 0){
            rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port"
                "=%u, queue_id=%u\n", ret, 0, tx_queue_id);
        }
    }

    /* start device */
    ret = rte_eth_dev_start(0);
    if(ret < 0) {
        rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n", ret, 0);
    }

    /* wait for port up */
    check_all_ports_link_status(1, 1);

    /* FDIR support */
    struct rte_eth_fdir_info fdir_info;
    memset(&fdir_info, 0, sizeof(struct rte_eth_fdir_info));
    rte_eth_dev_filter_ctrl(0, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_INFO, &fdir_info);

    err = rte_eth_dev_filter_supported(0, RTE_ETH_FILTER_FDIR);
    if (err < 0)
        printf("port0 does not support fdir !!\n");
    else
        printf("port0 supports fdir !!\n");

    err = rte_eth_dev_filter_ctrl(0, RTE_ETH_FILTER_FDIR, RTE_ETH_FILTER_FLUSH, NULL);
    if (err < 0)
        printf("port0 fail to flush fdir !!\n");
    else
        printf("port0 fdir flushed !!\n");

    /* setup fdir-filter */
    fdir_filter(1, //uint32_t soft_id,
                0, //(23<<24)+(0<<16)+(0<<8)+224, // uint32_t src_ip,
                (23<<24)+(0<<16)+(0<<8)+224, // uint32_t dst_ip,
                0, //uint16_t src_port,
                0, //5230, //uint16_t dst_port,
                RTE_ETH_FDIR_ACCEPT, //enum rte_eth_fdir_behavior fdir_behavior,
                0, //uint8_t port,
                6, //uint16_t rx_queue,
                RTE_ETH_FILTER_ADD //enum rte_filter_op op_code)
        );
    fdir_filter(2, //uint32_t soft_id,
                0, //(23<<24)+(0<<16)+(0<<8)+224, // uint32_t src_ip,
                (23<<24)+(1<<16)+(1<<8)+224, // uint32_t dst_ip,
                0, //uint16_t src_port,
                1, //5231, //uint16_t dst_port,
                RTE_ETH_FDIR_ACCEPT, //enum rte_eth_fdir_behavior fdir_behavior,
                0, //uint8_t port,
                7, //uint16_t rx_queue,
                RTE_ETH_FILTER_ADD //enum rte_filter_op op_code)
        );
    rte_eth_promiscuous_enable(0);
    printf("promiscuous mode for port0 enabled\n");

    /* entering the main loop */
    //main_loop(NULL);
    rte_eal_mp_remote_launch(main_loop, NULL, /*CALL_MASTER*/SKIP_MASTER);
    RTE_LCORE_FOREACH_SLAVE(lcore_id){
        if(rte_eal_wait_lcore(lcore_id) < 0) {
            fprintf(stderr, "fail to wait lcore %d !\n", lcore_id);
            return -1;
        }
    }

    while (1) {
        sleep(10);
    }

    return 0;
}
