# DPDK-Based Packet Processing Platform

A high-performance, userspace **packet processing engine** built in C using **DPDK 22.11 LTS**.
This project implements the core **data plane forwarding pipeline** found in modern data center
routers and switches, using kernel-bypass I/O, Poll Mode Drivers, and a modular forwarding
architecture across four independent processing modules.

---

## Why This Project Exists

Modern data centers — especially those running AI/ML workloads — move **millions of packets
per second** between GPU clusters, storage nodes, and compute racks. The traditional Linux
kernel networking stack cannot handle this at scale:

- Every packet triggers a **hardware interrupt**
- Data is **copied** between kernel and userspace buffers
- **Context switches** add latency at every hop

**DPDK solves this** by giving the application **direct access to the NIC**, bypassing the
kernel entirely:

```
Traditional Linux path:
NIC --> Kernel interrupt --> Kernel buffer --> Copy --> Userspace app
                    (slow, unpredictable latency, high CPU overhead)

DPDK kernel-bypass path:
NIC --> Userspace app (direct, zero-copy, poll mode)
                    (fast, predictable, line-rate capable)
```

This is the same principle used in production high-performance routers, cloud hypervisors
like AWS Nitro, and SmartNIC offload engines.

---

## Architecture

```
+================================================================+
|              DPDK Packet Processing Pipeline                   |
+================================================================+
|                                                                |
|   Port 0 (dtap0)                    Port 1 (dtap1)            |
|       |                                   ^                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   |  RX Burst |  poll mode, 32 pkts/call, no interrupts       |
|   +-----------+                           |                   |
|       |                                   |                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   |    ACL    |  5-tuple match, TCAM-style top-down           |
|   |   Engine  |  deny/permit before any forwarding            |
|   +-----------+                           |                   |
|       |                                   |                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   |   MPLS    |  label swap / pop / push                      |
|   |  Handler  |  ethertype 0x8847 detection                   |
|   +-----------+                           |                   |
|       |                                   |                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   |  L3 LPM   |  longest prefix match IPv4 route lookup       |
|   |  Lookup   |  next-hop MAC resolution                      |
|   +-----------+                           |                   |
|       |                                   |                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   |   ECMP    |  Jenkins hash on 5-tuple                      |
|   |   Hash    |  equal-cost multipath path selection          |
|   +-----------+                           |                   |
|       |                                   |                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   |  VxLAN    |  encap: wrap frame in outer ETH/IP/UDP        |
|   |  Engine   |  decap: strip outer headers, extract VNI      |
|   +-----------+                           |                   |
|       |                                   |                   |
|       v                                   |                   |
|   +-----------+                           |                   |
|   | TTL + ETH |  decrement TTL, rewrite dst MAC               |
|   |  Rewrite  |  standard L3 forwarding behavior              |
|   +-----------+                           |                   |
|       |                                   |                   |
|       +-----------------------------------+                   |
|                  TX Burst out correct port                     |
|                                                                |
+================================================================+
|       Live telemetry printed every 2 seconds per port          |
|       RX pkts | RX bytes | TX pkts | Dropped                   |
+================================================================+
```

---

## Features

| Feature | Description |
|---|---|
| **Kernel-bypass I/O** | DPDK Poll Mode Drivers, zero kernel involvement in packet path |
| **IPv4 L3 Forwarding** | LPM-based route lookup with Ethernet header rewrite and TTL decrement |
| **MPLS Label Switching** | Push / Pop / Swap with static label forwarding table |
| **VxLAN Overlay** | Full encap/decap with VTEP table and VNI-based tenant routing |
| **ACL Filtering** | 5-tuple rule matching, top-down first-match, TCAM-style evaluation |
| **ECMP Load Balancing** | Jenkins hash on src IP, dst IP, src port, dst port, protocol |
| **Live Telemetry** | Per-port RX/TX/drop counters refreshed every 2 seconds |
| **Graceful Shutdown** | Signal handling, final ACL stats and port stats printed on exit |

---

## What Each Module Does

### 1. ACL Engine (`src/acl.c` / `src/acl.h`)

The Access Control List engine evaluates every incoming packet against a rule table
**before any forwarding decision is made**. This mirrors how TCAM (Ternary Content
Addressable Memory) operates on custom ASICs in production routers — rules are
evaluated in order and the first match wins.

**How it works:**
- Each rule specifies: src IP + mask, dst IP + mask, protocol, src port, dst port, action
- Fields set to `0` act as wildcards — match any value
- Evaluation is **top-down**, first match wins — identical to real TCAM behavior
- On **DENY**: packet buffer is freed immediately, drop counter incremented
- On **PERMIT**: packet moves to the next pipeline stage
- At shutdown: total permitted and denied packet counts are printed

**Default ruleset:**
```
No.  Rule                        Action
1    DENY-HOST-10.0.0.99         DENY    block a specific malicious host
2    DENY-TELNET-23              DENY    block Telnet (plaintext, insecure)
3    DENY-RPC-135                DENY    block Windows RPC exploitation vector
4    PERMIT-TRUSTED-10.0.1.0/24  PERMIT  allow known trusted subnet
5    PERMIT-TRUSTED-10.0.2.0/24  PERMIT  allow known trusted subnet
6    DEFAULT-DENY-ALL            DENY    implicit deny, drop everything else
```

---

### 2. MPLS Engine (`src/mpls.c` / `src/mpls.h`)

MPLS (Multi-Protocol Label Switching) replaces per-hop IP lookups with fast label
operations. The ingress router pushes a **4-byte label** onto the packet — every
downstream router reads only the label, no IP lookup needed.

**MPLS header format (4 bytes total):**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Label (20 bits)         | TC |S|     TTL     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Label : 20-bit forwarding identifier
TC    : 3-bit traffic class (QoS marking)
S     : 1-bit bottom-of-stack indicator
TTL   : 8-bit time to live
```

**Three operations implemented:**

| Operation | What happens to the packet |
|---|---|
| **PUSH** | Prepend 4-byte MPLS header after Ethernet header, set label + TTL + S-bit, update ethertype to 0x8847 |
| **SWAP** | Replace incoming label field with new outgoing label, decrement TTL |
| **POP** | Strip the 4-byte MPLS header entirely, expose inner IPv4, restore ethertype to 0x0800 |

**Static label forwarding table:**
```
In-Label   Out-Label   Out-Port   Action
100        200         1          SWAP
200        0           0          POP  (exposes inner IPv4)
300        400         1          SWAP
```

Detection: ethertype `0x8847` on the Ethernet header triggers the MPLS path.

---

### 3. VxLAN Engine (`src/vxlan.c` / `src/vxlan.h`)

VxLAN (Virtual Extensible LAN) carries isolated tenant traffic over a shared physical
network fabric. Each tenant is identified by a 24-bit **VNI (Virtual Network Identifier)**
— supporting up to 16 million isolated virtual networks over one physical underlay.

**Encapsulation — what gets added to the packet:**
```
Before encap (inner frame):
[ Ethernet | IP | TCP/UDP | Payload ]

After encap (outer tunnel added):
[ outer ETH | outer IP | UDP (port 4789) | VxLAN header | Ethernet | IP | TCP/UDP | Payload ]
                          ^-- IANA port --^  ^-- VNI ----^
```

Total bytes added per encap: **50 bytes**
(Ethernet 14 + IP 20 + UDP 8 + VxLAN 8)

**VxLAN header format (8 bytes):**
```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|R|R|R|I|R|R|R|                 Reserved                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|              VNI (24 bits)            |      Reserved (8)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

I = 1 means VNI field is valid
UDP dst port = 4789 (IANA assigned for VxLAN)
```

**VTEP (Virtual Tunnel Endpoint) table:**
```
VNI   Local VTEP IP    Remote VTEP IP   Out-Port
100   192.168.1.1      192.168.1.2      1
200   192.168.2.1      192.168.2.2      0
```

**Decapsulation:** strips the outer 50 bytes, extracts VNI for tenant lookup, exposes
the original inner Ethernet frame for further processing.

---

### 4. L3 Forwarding + ECMP (`src/main.c`)

**LPM Route Lookup (Longest Prefix Match):**

Each packet's destination IP is compared against the routing table using a bitmask.
The most specific matching prefix wins — this is the fundamental algorithm used in
every IP router on the internet.

```c
/* How LPM works in this implementation */
uint32_t mask = ~(0xFFFFFFFF >> prefix_len);
if ((dst_ip & mask) == (route.dst_ip & mask))
    /* match — use this route */
```

**ECMP (Equal-Cost Multi-Path) via Jenkins Hash:**

When multiple equal-cost paths exist to a destination, DPDK's `rte_jhash()` hashes
the packet's 5-tuple to consistently send the **same flow down the same path** — this
is critical for TCP, which breaks if packets arrive out of order.

```
5-tuple input:
  src_ip + dst_ip + src_port + dst_port + protocol
                        |
                   rte_jhash()
                        |
               hash % num_paths
                        |
                  selected path index
```

This technique is used in spine-leaf data center fabrics to distribute AI training
traffic evenly across all available uplinks without breaking flow ordering.

---

## DPDK APIs Used

| API | Where used | Purpose |
|---|---|---|
| `rte_eal_init()` | `main()` | Initialize DPDK runtime, CPU, and memory |
| `rte_pktmbuf_pool_create()` | `main()` | Create mempool for zero-copy packet buffers |
| `rte_eth_dev_configure()` | `port_init()` | Configure RX/TX queues on each port |
| `rte_eth_rx_burst()` | `forwarding_loop()` | Poll-mode RX, fetch up to 32 packets |
| `rte_eth_tx_burst()` | `forwarding_loop()` | Poll-mode TX, send without kernel |
| `rte_pktmbuf_mtod()` | all modules | Direct pointer to packet data, zero copy |
| `rte_pktmbuf_prepend()` | `vxlan_encap()`, `mpls_push()` | Add header bytes at front |
| `rte_pktmbuf_adj()` | `vxlan_decap()`, `mpls_pop()` | Strip header bytes from front |
| `rte_jhash()` | `ecmp_select()` | Jenkins hash for ECMP path selection |
| `rte_get_tsc_cycles()` | `forwarding_loop()` | High-res timer for stats interval |
| `rte_be_to_cpu_32()` | all modules | Network to host byte order conversion |
| `TAP PMD` | EAL args | Virtual NIC driver, no physical hardware needed |

---

## Project Structure

```
dpdk-l3fwd/
├── src/
│   ├── main.c      # EAL init, port setup, forwarding loop, telemetry
│   ├── acl.c       # ACL rule engine — 5-tuple matching and enforcement
│   ├── acl.h       # ACL rule structs, action defines, function declarations
│   ├── mpls.c      # MPLS push / pop / swap operations
│   ├── mpls.h      # MPLS header format, label table structs, declarations
│   ├── vxlan.c     # VxLAN encap / decap, VTEP table management
│   └── vxlan.h     # VxLAN header format, tunnel structs, declarations
├── meson.build     # Meson build system configuration
├── scripts/        # Test and benchmark helper scripts
├── docs/           # Architecture and design documentation
└── README.md
```

---

## Build Instructions

### Step 1 — Install dependencies
```bash
sudo apt install meson ninja-build libnuma-dev \
  pkg-config python3-pyelftools build-essential wget
```

### Step 2 — Build and install DPDK 22.11
```bash
wget https://fast.dpdk.org/rel/dpdk-22.11.3.tar.xz
tar -xf dpdk-22.11.3.tar.xz
cd dpdk-stable-22.11.3
meson build --prefix=/usr/local
cd build && ninja && sudo ninja install && sudo ldconfig
cd ~
```

### Step 3 — Clone and build this project
```bash
git clone https://github.com/mivenzaro/dpdk-l3fwd.git
cd dpdk-l3fwd
meson setup build
cd build && ninja
```

---

## Run

```bash
sudo ./build/l3fwd \
  --vdev=net_tap0,iface=dtap0 \
  --vdev=net_tap1,iface=dtap1 \
  -l 0-1 --no-pci --no-huge -m 512 \
  --
```

---

## Live Output

```
[*] DPDK ports available: 2
[+] Port 0 initialised (TAP PMD)
[+] Port 1 initialised (TAP PMD)

=== MPLS Forwarding Table ===
In-Label   Out-Label  Out-Port  Action
--------------------------------------------
100        200        1         SWAP
200        0          0         POP
300        400        1         SWAP
============================

=== VxLAN Tunnel Table ===
VNI    Local VTEP        Remote VTEP       Out-Port
--------------------------------------------------
100    192.168.1.1       192.168.1.2       1
200    192.168.2.1       192.168.2.2       0
==========================

=== ACL Rule Table ===
No.  Rule Name                    Action
--------------------------------------------------
1    DENY-HOST-10.0.0.99          DENY
2    DENY-TELNET-23               DENY
3    DENY-RPC-135                 DENY
4    PERMIT-TRUSTED-10.0.1.0/24   PERMIT
5    PERMIT-TRUSTED-10.0.2.0/24   PERMIT
6    DEFAULT-DENY-ALL             DENY
======================

[*] L3 forwarder running on 2 ports. Ctrl+C to stop.

=============================================
       DPDK L3 Forwarder - Live Stats
=============================================
Port 0 | RX     13 pkts      1006 B | TX    0 | Drop   13
Port 1 | RX     13 pkts      1006 B | TX    0 | Drop   13
=============================================
```

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | C (C11 standard) |
| Packet I/O | DPDK 22.11 LTS, TAP Poll Mode Driver |
| Build system | Meson + Ninja |
| Operating system | Ubuntu 24.04 LTS (WSL2) |
| Architecture | x86_64, 12 logical cores |
| Hashing | Jenkins hash via `rte_jhash` |
| Memory | DPDK mempool, zero-copy mbufs |

---

## Roadmap

- [ ] FastAPI control plane with REST APIs for runtime table management
- [ ] Shared memory IPC between Python control plane and C dataplane
- [ ] Prometheus metrics endpoint for per-port telemetry scraping
- [ ] Grafana dashboard for live packet processing visualization
- [ ] Multi-core packet processing using DPDK lcore model
- [ ] Kafka event streaming for ACL deny and security events
- [ ] Docker containerization of control plane and dataplane
- [ ] Kubernetes and Helm deployment architecture

---

## Use Cases

| Use Case | How this platform addresses it |
|---|---|
| **AI cluster networking** | ECMP distributes GPU-to-GPU east-west traffic evenly across all paths |
| **Multi-tenant DC fabric** | VxLAN isolates up to 16M tenants over shared physical underlay |
| **Traffic engineering** | MPLS label switching steers flows across optimal paths |
| **Security enforcement** | ACL drops unauthorized traffic before any forwarding decision |
| **Cloud edge routing** | L3 LPM handles inter-subnet packet forwarding at line rate |

---

## Author

**Varsha Devanand**
Software Engineer
[GitHub](https://github.com/mivenzaro)