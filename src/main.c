#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <inttypes.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_lpm.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_log.h>

#include "mpls.h"
#include "vxlan.h"
#include "acl.h"

#define RX_RING_SIZE     1024
#define TX_RING_SIZE     1024
#define NUM_MBUFS        8191
#define MBUF_CACHE_SIZE  250
#define BURST_SIZE       32
#define MAX_PORTS        2

/* Per-port statistics */
struct port_stats {
    uint64_t rx_pkts;
    uint64_t tx_pkts;
    uint64_t dropped;
    uint64_t rx_bytes;
} __rte_cache_aligned;

static struct port_stats stats[MAX_PORTS];
static volatile int force_quit = 0;

/* Static routing table */
struct route_entry {
    uint32_t dst_ip;
    uint8_t  prefix_len;
    uint16_t out_port;
    struct rte_ether_addr next_hop_mac;
};

static struct route_entry routes[] = {
    {
        .dst_ip       = RTE_IPV4(10, 0, 1, 0),
        .prefix_len   = 24,
        .out_port     = 0,
        .next_hop_mac = { .addr_bytes = {0x02,0x00,0x00,0x00,0x00,0x01} }
    },
    {
        .dst_ip       = RTE_IPV4(10, 0, 2, 0),
        .prefix_len   = 24,
        .out_port     = 1,
        .next_hop_mac = { .addr_bytes = {0x02,0x00,0x00,0x00,0x00,0x02} }
    },
};
#define NUM_ROUTES (sizeof(routes) / sizeof(routes[0]))

static struct rte_mempool *mbuf_pool;

/* Signal handler */
static void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received - stopping forwarder.\n", signum);
        force_quit = 1;
    }
}

/* LPM route lookup */
static int lookup_route(uint32_t dst_ip,
                        uint16_t *out_port,
                        struct rte_ether_addr *nh_mac)
{
    for (size_t i = 0; i < NUM_ROUTES; i++) {
        uint32_t mask = (routes[i].prefix_len == 32)
                        ? 0xFFFFFFFF
                        : ~(0xFFFFFFFF >> routes[i].prefix_len);
        if ((dst_ip & mask) == (routes[i].dst_ip & mask)) {
            *out_port = routes[i].out_port;
            rte_ether_addr_copy(&routes[i].next_hop_mac, nh_mac);
            return 0;
        }
    }
    return -1;
}

/* ECMP 5-tuple hash */
static uint16_t ecmp_select(uint32_t src_ip, uint32_t dst_ip,
                             uint16_t sport,  uint16_t dport,
                             uint8_t  proto,  uint16_t num_paths)
{
    uint32_t key[4] = {
        src_ip,
        dst_ip,
        (uint32_t)(sport << 16 | dport),
        proto
    };
    return (uint16_t)(rte_jhash(key, sizeof(key), 0) % num_paths);
}

/* Port initialisation */
static int port_init(uint16_t port)
{
    struct rte_eth_conf port_conf = {
        .rxmode = { .max_lro_pkt_size = RTE_ETHER_MAX_LEN },
    };
    int ret;

    ret = rte_eth_dev_configure(port, 1, 1, &port_conf);
    if (ret != 0) return ret;

    ret = rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
            rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (ret < 0) return ret;

    ret = rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
            rte_eth_dev_socket_id(port), NULL);
    if (ret < 0) return ret;

    ret = rte_eth_dev_start(port);
    if (ret < 0) return ret;

    rte_eth_promiscuous_enable(port);
    printf("[+] Port %u initialised (TAP PMD)\n", port);
    return 0;
}

/* Stats printer */
static void print_stats(void)
{
    printf("\n=============================================\n");
    printf("       DPDK L3 Forwarder - Live Stats        \n");
    printf("=============================================\n");
    for (int p = 0; p < MAX_PORTS; p++) {
        printf("Port %d | RX %8"PRIu64" pkts %10"PRIu64" B"
               " | TX %8"PRIu64" | Drop %6"PRIu64"\n",
               p,
               stats[p].rx_pkts, stats[p].rx_bytes,
               stats[p].tx_pkts, stats[p].dropped);
    }
    printf("=============================================\n");
}

/* Main forwarding loop */
static void forwarding_loop(void)
{
    struct rte_mbuf *bufs[BURST_SIZE];
    uint64_t hz         = rte_get_tsc_hz();
    uint64_t last_stats = rte_get_tsc_cycles();

    printf("\n[*] L3 forwarder running on %u ports. Ctrl+C to stop.\n\n",
           RTE_MIN(rte_eth_dev_count_avail(), (uint16_t)MAX_PORTS));

    while (!force_quit) {

        for (uint16_t port = 0; port < MAX_PORTS; port++) {

            uint16_t nb_rx = rte_eth_rx_burst(port, 0,
                                               bufs, BURST_SIZE);
            if (unlikely(nb_rx == 0))
                continue;

            stats[port].rx_pkts += nb_rx;

            for (uint16_t i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = bufs[i];
                struct rte_ether_hdr *eth =
                    rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                stats[port].rx_bytes += rte_pktmbuf_pkt_len(m);

                /* ACL check - drop denied packets */
                if (acl_check(m) < 0) {
                    rte_pktmbuf_free(m);
                    stats[port].dropped++;
                    continue;
                }

                /* MPLS handling */
                if (eth->ether_type ==
                        rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLS)) {
                    uint16_t out_port;
                    if (mpls_process(m, &out_port) < 0) {
                        rte_pktmbuf_free(m);
                        stats[port].dropped++;
                        continue;
                    }
                    uint16_t sent =
                        rte_eth_tx_burst(out_port, 0, &m, 1);
                    if (sent == 0) {
                        rte_pktmbuf_free(m);
                        stats[port].dropped++;
                    } else {
                        stats[out_port].tx_pkts++;
                    }
                    continue;
                }

                /* Drop non-IPv4 */
                if (eth->ether_type !=
                        rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                    rte_pktmbuf_free(m);
                    stats[port].dropped++;
                    continue;
                }

                struct rte_ipv4_hdr *ip =
                    (struct rte_ipv4_hdr *)(eth + 1);

                uint32_t dst = rte_be_to_cpu_32(ip->dst_addr);
                uint32_t src = rte_be_to_cpu_32(ip->src_addr);

                uint16_t out_port;
                struct rte_ether_addr nh_mac;

                /* Route lookup */
                if (lookup_route(dst, &out_port, &nh_mac) < 0) {
                    rte_pktmbuf_free(m);
                    stats[port].dropped++;
                    continue;
                }

                /* ECMP */
                uint16_t path = ecmp_select(src, dst,
                                    0, 0, ip->next_proto_id, 1);
                (void)path;

                /* TTL check */
                if (ip->time_to_live <= 1) {
                    rte_pktmbuf_free(m);
                    stats[port].dropped++;
                    continue;
                }
                ip->time_to_live--;

                /* Rewrite dst MAC */
                rte_ether_addr_copy(&nh_mac, &eth->dst_addr);

                /* Transmit */
                uint16_t sent = rte_eth_tx_burst(out_port, 0, &m, 1);
                if (sent == 0) {
                    rte_pktmbuf_free(m);
                    stats[port].dropped++;
                } else {
                    stats[out_port].tx_pkts++;
                }
            }
        }

        /* Print stats every 2s */
        uint64_t now = rte_get_tsc_cycles();
        if ((now - last_stats) > 2 * hz) {
            print_stats();
            last_stats = now;
        }
    }
}

/* Entry point */
int main(int argc, char *argv[])
{
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "EAL initialisation failed\n");

    uint16_t nb_ports = rte_eth_dev_count_avail();
    printf("[*] DPDK ports available: %u\n", nb_ports);
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE,
                 "No ports found - check TAP vdev args.\n");

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL",
        NUM_MBUFS * RTE_MAX(nb_ports, 1u),
        MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE,
        rte_socket_id());
    if (!mbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    uint16_t p;
    RTE_ETH_FOREACH_DEV(p) {
        if (p >= MAX_PORTS) break;
        if (port_init(p) != 0)
            rte_exit(EXIT_FAILURE, "Port %u init failed\n", p);
    }

    /* Print all tables on startup */
    mpls_print_table();
    vxlan_print_tunnels();
    acl_print_rules();

    forwarding_loop();

    /* Graceful shutdown */
    RTE_ETH_FOREACH_DEV(p) {
        if (p >= MAX_PORTS) break;
        rte_eth_dev_stop(p);
        rte_eth_dev_close(p);
    }

    acl_print_stats();
    print_stats();
    printf("\n[*] Forwarder stopped. Goodbye.\n");
    rte_eal_cleanup();
    return 0;
}