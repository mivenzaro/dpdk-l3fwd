#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include "acl.h"
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

/* ── Static ACL rule table ──
   Rules are evaluated top-down, first match wins.
   This mirrors how TCAM works on Nokia's ASICs. */

static struct acl_rule acl_table[] = {
    /* Block traffic from a specific host */
    {
        .src_ip   = RTE_IPV4(10, 0, 0, 99),
        .src_mask = 0xFFFFFFFF,
        .dst_ip   = 0, .dst_mask = 0,
        .proto    = 0,
        .src_port = 0, .dst_port = 0,
        .action   = ACL_ACTION_DENY,
        .name     = "DENY-HOST-10.0.0.99"
    },
    /* Block all traffic to port 23 (Telnet) */
    {
        .src_ip   = 0, .src_mask = 0,
        .dst_ip   = 0, .dst_mask = 0,
        .proto    = 6,   /* TCP */
        .src_port = 0,
        .dst_port = 23,
        .action   = ACL_ACTION_DENY,
        .name     = "DENY-TELNET-23"
    },
    /* Block all traffic to port 135 (Windows RPC) */
    {
        .src_ip   = 0, .src_mask = 0,
        .dst_ip   = 0, .dst_mask = 0,
        .proto    = 6,   /* TCP */
        .src_port = 0,
        .dst_port = 135,
        .action   = ACL_ACTION_DENY,
        .name     = "DENY-RPC-135"
    },
    /* Permit traffic from trusted subnet 10.0.1.0/24 */
    {
        .src_ip   = RTE_IPV4(10, 0, 1, 0),
        .src_mask = 0xFFFFFF00,
        .dst_ip   = 0, .dst_mask = 0,
        .proto    = 0,
        .src_port = 0, .dst_port = 0,
        .action   = ACL_ACTION_PERMIT,
        .name     = "PERMIT-TRUSTED-10.0.1.0/24"
    },
    /* Permit traffic from trusted subnet 10.0.2.0/24 */
    {
        .src_ip   = RTE_IPV4(10, 0, 2, 0),
        .src_mask = 0xFFFFFF00,
        .dst_ip   = 0, .dst_mask = 0,
        .proto    = 0,
        .src_port = 0, .dst_port = 0,
        .action   = ACL_ACTION_PERMIT,
        .name     = "PERMIT-TRUSTED-10.0.2.0/24"
    },
    /* Default deny all — implicit last rule */
    {
        .src_ip   = 0, .src_mask = 0,
        .dst_ip   = 0, .dst_mask = 0,
        .proto    = 0,
        .src_port = 0, .dst_port = 0,
        .action   = ACL_ACTION_DENY,
        .name     = "DEFAULT-DENY-ALL"
    },
};
#define ACL_TABLE_SIZE (sizeof(acl_table)/sizeof(acl_table[0]))

/* Global ACL stats */
static struct acl_stats stats = {0, 0};

/* ── Match a single rule against packet fields ── */
static int rule_matches(struct acl_rule *rule,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint8_t proto,
                        uint16_t src_port, uint16_t dst_port)
{
    /* Source IP check */
    if (rule->src_mask &&
        (src_ip & rule->src_mask) != (rule->src_ip & rule->src_mask))
        return 0;

    /* Destination IP check */
    if (rule->dst_mask &&
        (dst_ip & rule->dst_mask) != (rule->dst_ip & rule->dst_mask))
        return 0;

    /* Protocol check */
    if (rule->proto && rule->proto != proto)
        return 0;

    /* Source port check */
    if (rule->src_port && rule->src_port != src_port)
        return 0;

    /* Destination port check */
    if (rule->dst_port && rule->dst_port != dst_port)
        return 0;

    return 1; /* match */
}

/* ── Main ACL check function ──
   Returns 0 = PERMIT, -1 = DENY */
int acl_check(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Only process IPv4 */
    if (eth->ether_type !=
            rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return 0; /* non-IP — permit by default */

    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(eth + 1);

    uint32_t src_ip = rte_be_to_cpu_32(ip->src_addr);
    uint32_t dst_ip = rte_be_to_cpu_32(ip->dst_addr);
    uint8_t  proto  = ip->next_proto_id;

    uint16_t src_port = 0, dst_port = 0;

    /* Extract ports for TCP/UDP */
    if (proto == 6) { /* TCP */
        struct rte_tcp_hdr *tcp =
            (struct rte_tcp_hdr *)(ip + 1);
        src_port = rte_be_to_cpu_16(tcp->src_port);
        dst_port = rte_be_to_cpu_16(tcp->dst_port);
    } else if (proto == 17) { /* UDP */
        struct rte_udp_hdr *udp =
            (struct rte_udp_hdr *)(ip + 1);
        src_port = rte_be_to_cpu_16(udp->src_port);
        dst_port = rte_be_to_cpu_16(udp->dst_port);
    }

    /* Evaluate rules top-down — first match wins */
    for (size_t i = 0; i < ACL_TABLE_SIZE; i++) {
        if (rule_matches(&acl_table[i],
                         src_ip, dst_ip,
                         proto,
                         src_port, dst_port)) {
            if (acl_table[i].action == ACL_ACTION_PERMIT) {
                stats.permitted++;
                return 0;  /* PERMIT */
            } else {
                stats.denied++;
                printf("[ACL] DENY — rule: %s\n",
                       acl_table[i].name);
                return -1; /* DENY */
            }
        }
    }

    /* No match — default permit */
    stats.permitted++;
    return 0;
}

/* ── Print ACL rule table ── */
void acl_print_rules(void)
{
    printf("\n=== ACL Rule Table ===\n");
    printf("%-4s %-30s %s\n", "No.", "Rule Name", "Action");
    printf("--------------------------------------------------\n");
    for (size_t i = 0; i < ACL_TABLE_SIZE; i++) {
        printf("%-4zu %-30s %s\n",
               i + 1,
               acl_table[i].name,
               acl_table[i].action == ACL_ACTION_PERMIT
                   ? "PERMIT" : "DENY");
    }
    printf("======================\n\n");
}

/* ── Print ACL stats ── */
void acl_print_stats(void)
{
    printf("\n=== ACL Stats ===\n");
    printf("Permitted : %lu\n", stats.permitted);
    printf("Denied    : %lu\n", stats.denied);
    printf("=================\n");
}