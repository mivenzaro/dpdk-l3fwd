#ifndef ACL_H
#define ACL_H

#include <sys/types.h>
#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>

/* ACL actions */
#define ACL_ACTION_PERMIT  0
#define ACL_ACTION_DENY    1

/* ACL rule — matches on 5-tuple */
struct acl_rule {
    uint32_t src_ip;      /* source IP to match (0 = wildcard) */
    uint32_t src_mask;    /* source IP mask */
    uint32_t dst_ip;      /* destination IP to match (0 = wildcard) */
    uint32_t dst_mask;    /* destination IP mask */
    uint8_t  proto;       /* IP protocol (0 = wildcard) */
    uint16_t src_port;    /* source port (0 = wildcard) */
    uint16_t dst_port;    /* destination port (0 = wildcard) */
    uint8_t  action;      /* ACL_ACTION_PERMIT or ACL_ACTION_DENY */
    const char *name;     /* rule name for logging */
};

/* ACL stats */
struct acl_stats {
    uint64_t permitted;
    uint64_t denied;
};

/* Function declarations */
int  acl_check(struct rte_mbuf *m);
void acl_print_rules(void);
void acl_print_stats(void);

#endif /* ACL_H */