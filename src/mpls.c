#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include "mpls.h"
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>

/* ── Static MPLS forwarding table ──
   In a real router this is populated by a control plane (LDP/RSVP).
   Here we define it statically for demonstration. */

static struct mpls_entry mpls_table[] = {
    /* in_label  out_label  out_port  action      */
    {  100,      200,       1,        MPLS_ACTION_SWAP  },
    {  200,      0,         0,        MPLS_ACTION_POP   },
    {  300,      400,       1,        MPLS_ACTION_SWAP  },
};
#define MPLS_TABLE_SIZE (sizeof(mpls_table)/sizeof(mpls_table[0]))

/* ── Lookup label in forwarding table ── */
struct mpls_entry *mpls_lookup(uint32_t label)
{
    for (size_t i = 0; i < MPLS_TABLE_SIZE; i++) {
        if (mpls_table[i].in_label == label)
            return &mpls_table[i];
    }
    return NULL;
}

/* ── MPLS POP: remove top label, expose inner IP ── */
int mpls_pop(struct rte_mbuf *m)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Move ethernet header forward by 4 bytes (size of MPLS header) */
    memmove((uint8_t *)eth + sizeof(struct mpls_hdr),
             eth,
             sizeof(struct rte_ether_hdr));

    /* Advance data pointer */
    if (rte_pktmbuf_adj(m, sizeof(struct mpls_hdr)) == NULL)
        return -1;

    /* Update ethertype to IPv4 */
    eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    printf("[MPLS] POP — exposed inner IPv4\n");
    return 0;
}

/* ── MPLS SWAP: replace top label ── */
int mpls_swap(struct rte_mbuf *m, uint32_t new_label)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct mpls_hdr *mpls =
        (struct mpls_hdr *)(eth + 1);

    uint8_t old_ttl = mpls_get_ttl(mpls->tag);
    if (old_ttl <= 1) return -1;  /* TTL expired */

    mpls->tag = mpls_build_tag(new_label, old_ttl - 1, 1);
    printf("[MPLS] SWAP label → %u\n", new_label);
    return 0;
}

/* ── MPLS PUSH: prepend a new label ── */
int mpls_push(struct rte_mbuf *m, uint32_t label, uint8_t ttl)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Prepend 4 bytes at the front */
    struct rte_ether_hdr *new_eth =
        (struct rte_ether_hdr *)rte_pktmbuf_prepend(m,
            sizeof(struct mpls_hdr));
    if (!new_eth) return -1;

    /* Copy ethernet header to new position */
    memmove(new_eth, eth, sizeof(struct rte_ether_hdr));

    /* Write MPLS header after ethernet */
    struct mpls_hdr *mpls = (struct mpls_hdr *)(new_eth + 1);
    mpls->tag = mpls_build_tag(label, ttl, 1);

    /* Update ethertype */
    new_eth->ether_type =
        rte_cpu_to_be_16(RTE_ETHER_TYPE_MPLS);

    printf("[MPLS] PUSH label %u\n", label);
    return 0;
}

/* ── Main MPLS processing function ──
   Called from forwarding loop when ethertype = 0x8847 */
int mpls_process(struct rte_mbuf *m, uint16_t *out_port)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    struct mpls_hdr *mpls =
        (struct mpls_hdr *)(eth + 1);

    uint32_t label = mpls_get_label(mpls->tag);
    printf("[MPLS] Received packet with label %u\n", label);

    struct mpls_entry *entry = mpls_lookup(label);
    if (!entry) {
        printf("[MPLS] No entry for label %u — dropping\n", label);
        return -1;
    }

    *out_port = entry->out_port;

    switch (entry->action) {
    case MPLS_ACTION_POP:
        return mpls_pop(m);

    case MPLS_ACTION_SWAP:
        return mpls_swap(m, entry->out_label);

    case MPLS_ACTION_PUSH:
        return mpls_push(m, entry->out_label, 64);

    default:
        return -1;
    }
}

/* ── Print MPLS forwarding table ── */
void mpls_print_table(void)
{
    printf("\n=== MPLS Forwarding Table ===\n");
    printf("%-12s %-12s %-10s %s\n",
           "In-Label", "Out-Label", "Out-Port", "Action");
    printf("--------------------------------------------\n");
    for (size_t i = 0; i < MPLS_TABLE_SIZE; i++) {
        const char *action =
            mpls_table[i].action == MPLS_ACTION_SWAP ? "SWAP" :
            mpls_table[i].action == MPLS_ACTION_POP  ? "POP"  :
                                                        "PUSH";
        printf("%-12u %-12u %-10u %s\n",
               mpls_table[i].in_label,
               mpls_table[i].out_label,
               mpls_table[i].out_port,
               action);
    }
    printf("============================\n\n");
}