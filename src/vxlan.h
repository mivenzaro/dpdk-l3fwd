#ifndef VXLAN_H
#define VXLAN_H

#include <sys/types.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

/* VxLAN UDP port (IANA assigned) */
#define VXLAN_PORT      4789
#define VXLAN_HDR_SIZE  8

/* VxLAN header:
   [8-bit flags | 24-bit reserved | 24-bit VNI | 8-bit reserved] */
struct vxlan_hdr {
    uint32_t vx_flags;   /* flags + reserved */
    uint32_t vx_vni;     /* VNI (top 24 bits) + reserved (low 8) */
} __rte_packed;

/* VxLAN tunnel entry */
struct vxlan_tunnel {
    uint32_t vni;         /* Virtual Network Identifier */
    uint32_t local_ip;    /* local VTEP IP */
    uint32_t remote_ip;   /* remote VTEP IP */
    uint16_t out_port;    /* output port */
    struct rte_ether_addr local_mac;
    struct rte_ether_addr remote_mac;
};

#define VXLAN_FLAG_I    0x08000000  /* valid VNI flag */

/* Extract VNI from vxlan header */
static inline uint32_t vxlan_get_vni(uint32_t vx_vni) {
    return (rte_be_to_cpu_32(vx_vni) >> 8) & 0xFFFFFF;
}

/* Build VNI field */
static inline uint32_t vxlan_build_vni(uint32_t vni) {
    return rte_cpu_to_be_32(vni << 8);
}

/* Function declarations */
int  vxlan_encap(struct rte_mbuf *m, struct vxlan_tunnel *t);
int  vxlan_decap(struct rte_mbuf *m, uint32_t *vni_out);
struct vxlan_tunnel *vxlan_lookup(uint32_t vni);
void vxlan_print_tunnels(void);

#endif /* VXLAN_H */