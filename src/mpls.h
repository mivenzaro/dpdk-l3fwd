#ifndef MPLS_H
#define MPLS_H

#include <sys/types.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

#define MPLS_LABEL_SHIFT    12
#define MPLS_TTL_MASK       0xFF
#define MPLS_S_BIT          0x100
#define RTE_ETHER_TYPE_MPLS 0x8847

/* MPLS header: 4 bytes */
struct mpls_hdr {
    uint32_t tag;
} __rte_packed;

/* MPLS forwarding table entry */
struct mpls_entry {
    uint32_t in_label;
    uint32_t out_label;
    uint16_t out_port;
    uint8_t  action;
};

#define MPLS_ACTION_SWAP  0
#define MPLS_ACTION_POP   1
#define MPLS_ACTION_PUSH  2

/* Inline helpers */
static inline uint32_t mpls_get_label(uint32_t tag) {
    return (rte_be_to_cpu_32(tag) >> 12) & 0xFFFFF;
}

static inline uint8_t mpls_get_ttl(uint32_t tag) {
    return rte_be_to_cpu_32(tag) & 0xFF;
}

static inline uint32_t mpls_build_tag(uint32_t label,
                                       uint8_t ttl,
                                       uint8_t bottom) {
    uint32_t tag = (label << 12) | ttl;
    if (bottom) tag |= MPLS_S_BIT;
    return rte_cpu_to_be_32(tag);
}

/* Function declarations — visible to main.c */
int  mpls_process(struct rte_mbuf *m, uint16_t *out_port);
void mpls_print_table(void);

#endif /* MPLS_H */