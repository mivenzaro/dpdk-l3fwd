#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include "vxlan.h"
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_byteorder.h>

/* ── Static VxLAN tunnel table ──
   In production this is populated by control plane (BGP EVPN).
   Here we define two tunnels statically for demonstration. */

static struct vxlan_tunnel tunnel_table[] = {
    {
        .vni        = 100,
        .local_ip   = RTE_IPV4(192, 168, 1, 1),
        .remote_ip  = RTE_IPV4(192, 168, 1, 2),
        .out_port   = 1,
        .local_mac  = { .addr_bytes = {0x02,0x00,0x00,0x00,0x01,0x01} },
        .remote_mac = { .addr_bytes = {0x02,0x00,0x00,0x00,0x01,0x02} },
    },
    {
        .vni        = 200,
        .local_ip   = RTE_IPV4(192, 168, 2, 1),
        .remote_ip  = RTE_IPV4(192, 168, 2, 2),
        .out_port   = 0,
        .local_mac  = { .addr_bytes = {0x02,0x00,0x00,0x00,0x02,0x01} },
        .remote_mac = { .addr_bytes = {0x02,0x00,0x00,0x00,0x02,0x02} },
    },
};
#define TUNNEL_TABLE_SIZE (sizeof(tunnel_table)/sizeof(tunnel_table[0]))

/* ── Lookup tunnel by VNI ── */
struct vxlan_tunnel *vxlan_lookup(uint32_t vni)
{
    for (size_t i = 0; i < TUNNEL_TABLE_SIZE; i++) {
        if (tunnel_table[i].vni == vni)
            return &tunnel_table[i];
    }
    return NULL;
}

/* ── VxLAN ENCAP ──
   Wraps inner Ethernet frame with:
   outer ETH / outer IP / UDP / VxLAN header */
int vxlan_encap(struct rte_mbuf *m, struct vxlan_tunnel *t)
{
    /* Calculate total header size to prepend:
       Ethernet(14) + IP(20) + UDP(8) + VxLAN(8) = 50 bytes */
    uint16_t encap_len = sizeof(struct rte_ether_hdr)
                       + sizeof(struct rte_ipv4_hdr)
                       + sizeof(struct rte_udp_hdr)
                       + sizeof(struct vxlan_hdr);

    /* Prepend space */
    char *new_hdr = rte_pktmbuf_prepend(m, encap_len);
    if (!new_hdr) {
        printf("[VxLAN] ENCAP failed — no headroom\n");
        return -1;
    }

    /* ── Outer Ethernet header ── */
    struct rte_ether_hdr *eth =
        (struct rte_ether_hdr *)new_hdr;
    rte_ether_addr_copy(&t->remote_mac, &eth->dst_addr);
    rte_ether_addr_copy(&t->local_mac,  &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* ── Outer IP header ── */
    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(eth + 1);
    memset(ip, 0, sizeof(*ip));
    ip->version_ihl     = 0x45;   /* IPv4, 20-byte header */
    ip->type_of_service = 0;
    ip->total_length    = rte_cpu_to_be_16(
        rte_pktmbuf_pkt_len(m) - sizeof(struct rte_ether_hdr));
    ip->time_to_live    = 64;
    ip->next_proto_id   = IPPROTO_UDP;
    ip->src_addr        = rte_cpu_to_be_32(t->local_ip);
    ip->dst_addr        = rte_cpu_to_be_32(t->remote_ip);
    ip->hdr_checksum    = 0;  /* offload or compute later */

    /* ── UDP header ── */
    struct rte_udp_hdr *udp =
        (struct rte_udp_hdr *)(ip + 1);
    udp->src_port    = rte_cpu_to_be_16(49152); /* ephemeral */
    udp->dst_port    = rte_cpu_to_be_16(VXLAN_PORT);
    udp->dgram_len   = rte_cpu_to_be_16(
        rte_pktmbuf_pkt_len(m)
        - sizeof(struct rte_ether_hdr)
        - sizeof(struct rte_ipv4_hdr));
    udp->dgram_cksum = 0;

    /* ── VxLAN header ── */
    struct vxlan_hdr *vxh =
        (struct vxlan_hdr *)(udp + 1);
    vxh->vx_flags = rte_cpu_to_be_32(VXLAN_FLAG_I);
    vxh->vx_vni   = vxlan_build_vni(t->vni);

    printf("[VxLAN] ENCAP — VNI %u → remote %u.%u.%u.%u\n",
           t->vni,
           (t->remote_ip >> 24) & 0xFF,
           (t->remote_ip >> 16) & 0xFF,
           (t->remote_ip >>  8) & 0xFF,
           (t->remote_ip      ) & 0xFF);
    return 0;
}

/* ── VxLAN DECAP ──
   Strips outer ETH/IP/UDP/VxLAN headers,
   exposes inner Ethernet frame */
int vxlan_decap(struct rte_mbuf *m, uint32_t *vni_out)
{
    struct rte_ether_hdr *eth =
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

    /* Verify outer IP */
    struct rte_ipv4_hdr *ip =
        (struct rte_ipv4_hdr *)(eth + 1);
    if (ip->next_proto_id != IPPROTO_UDP) {
        printf("[VxLAN] DECAP — not UDP, dropping\n");
        return -1;
    }

    /* Verify UDP dst port */
    struct rte_udp_hdr *udp =
        (struct rte_udp_hdr *)(ip + 1);
    if (rte_be_to_cpu_16(udp->dst_port) != VXLAN_PORT) {
        printf("[VxLAN] DECAP — not VxLAN port, dropping\n");
        return -1;
    }

    /* Extract VNI */
    struct vxlan_hdr *vxh =
        (struct vxlan_hdr *)(udp + 1);
    *vni_out = vxlan_get_vni(vxh->vx_vni);

    /* Strip outer headers:
       ETH(14) + IP(20) + UDP(8) + VxLAN(8) = 50 bytes */
    uint16_t strip_len = sizeof(struct rte_ether_hdr)
                       + sizeof(struct rte_ipv4_hdr)
                       + sizeof(struct rte_udp_hdr)
                       + sizeof(struct vxlan_hdr);

    if (rte_pktmbuf_adj(m, strip_len) == NULL) {
        printf("[VxLAN] DECAP — adj failed\n");
        return -1;
    }

    printf("[VxLAN] DECAP — VNI %u extracted\n", *vni_out);
    return 0;
}

/* ── Print tunnel table ── */
void vxlan_print_tunnels(void)
{
    printf("\n=== VxLAN Tunnel Table ===\n");
    printf("%-6s %-18s %-18s %-10s\n",
           "VNI", "Local VTEP", "Remote VTEP", "Out-Port");
    printf("--------------------------------------------------\n");
    for (size_t i = 0; i < TUNNEL_TABLE_SIZE; i++) {
        uint32_t l = tunnel_table[i].local_ip;
        uint32_t r = tunnel_table[i].remote_ip;
        printf("%-6u %u.%u.%u.%u%-10s %u.%u.%u.%u%-10s %-10u\n",
               tunnel_table[i].vni,
               (l>>24)&0xFF, (l>>16)&0xFF,
               (l>> 8)&0xFF, (l    )&0xFF, "",
               (r>>24)&0xFF, (r>>16)&0xFF,
               (r>> 8)&0xFF, (r    )&0xFF, "",
               tunnel_table[i].out_port);
    }
    printf("==========================\n\n");
}