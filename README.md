# 🔐 ARP Spoofing Detection — Active Injection Technique

> A real-time ARP spoofing detector implemented in C using raw sockets and libpcap, based on the academic paper *"Detecting ARP Spoofing: An Active Technique"* by Ramachandran & Nandi (2005).

---

## 📋 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Detection Algorithm](#detection-algorithm)
- [Project Structure](#project-structure)
- [Data Structures](#data-structures)
- [Requirements](#requirements)
- [Build & Run](#build--run)
- [Key Constants](#key-constants)
- [Academic Context](#academic-context)
- [References](#references)

---

## Overview

ARP (Address Resolution Protocol) is stateless and has no authentication mechanism — any host on a LAN can claim to own any IP address. This makes it trivially vulnerable to **ARP Spoofing**, which is the entry point for:

- 🎭 **Man-in-the-Middle attacks** — intercept and read traffic between two hosts
- 💥 **Denial of Service** — associate an IP with a non-existent MAC
- 🔑 **Session Hijacking** — steal HTTP session cookies

This project implements an **active detection system** that injects ARP Request and TCP SYN packets into the network to verify the authenticity of every ARP reply it sees — in real time, without any prior learning phase.

```
passive approach  →  learns first, detects later  →  vulnerable at startup
active approach   →  verifies immediately          →  works from packet zero
```

---

## How It Works

```
Network Wire
    │
    ▼
NIC (promiscuous mode)
    │
    ▼
BPF Filter "arp"  ──── drops all non-ARP frames
    │
    ▼
callback()  ──── called by pcap_loop() for every ARP packet
    │
    ├── mac_addresses_match()   ← ether_shost vs arp_sha
    │       └── mismatch → SPOOF ALARM (Inconsistent Header)
    │
    ├── is_verifie_relation()   ← check Host Database
    │       └── known host → LEGITIMATE, skip
    │
    ├── [ARP REQUEST]
    │       ├── verification()          ← deduplicate
    │       ├── add_arp_request()       ← store in linked list
    │       └── send_syn_and_recv_syn_ack()  ← TCP SYN probe
    │
    └── [ARP REPLY]
            ├── is_reply()              ← match stored request
            │       └── matched → LEGITIMATE
            └── no match → response_half_cycle()
                    ├── send ARP broadcast probe
                    ├── wait 5 seconds (THRESHOLD_SEC)
                    ├── 0 replies  → SPOOF_DETECTED
                    ├── 1 reply, MAC match → TCP SYN verify
                    ├── 1 reply, MAC differ → SPOOF_DETECTED
                    └── 2+ replies → SPOOF_DETECTED
```

---

## Detection Algorithm

The system is based on two fundamental rules derived from standard TCP/IP stack behavior:

### Rule A — Normal TCP/IP Stack Behavior
> A host's NIC accepts packets sent to its MAC address. The IP layer **silently discards** packets whose destination IP does not match — without sending any error back.
>
> **Consequence:** A TCP SYN sent to the real MAC but wrong IP → silently dropped. Sent to the right MAC + right IP → SYN-ACK or RST. This lets us verify a host is real.

### Rule B — An Attacker Cannot Silence a Real Host
> An attacker can forge ARP replies impersonating a host, but **cannot prevent the real host from replying** to a broadcast ARP Request sent to the network.
>
> **Consequence:** If we send an ARP broadcast and get multiple replies for the same IP → spoofing confirmed.

### The Three ARP Cycles

| Cycle | Condition | Suspicion Level | Action |
|---|---|---|---|
| **Inconsistent Header** | `ether_shost ≠ arp_sha` | 🔴 Guaranteed spoofed | Immediate alarm |
| **Full ARP Cycle** | REQUEST + REPLY within threshold | 🟡 Possible if >1 reply | TCP SYN to each reply source |
| **Request Half Cycle** | REQUEST with no REPLY | 🟡 Sender suspect | TCP SYN to request source |
| **Response Half Cycle** | REPLY with no prior REQUEST | 🔴 Very suspicious | ARP broadcast probe + analysis |

### Response Half Cycle — Decision Tree

```
Unsolicited ARP REPLY received
         │
         ▼
Send broadcast ARP REQUEST for suspicious IP
         │
         ▼
Wait 5 seconds (SO_RCVTIMEO)
         │
    ┌────┴────────┬─────────────────┐
    │             │                 │
  0 replies   1 reply           2+ replies
    │          ├── MAC match?       │
    │          │   YES → TCP SYN    │
    │          │     ├── SYN-ACK → CLEAN
    │          │     └── timeout → DETECTED
    │          └── MAC differ → DETECTED
    │                              │
    └──────── SPOOF_DETECTED ──────┘
```

---

## Project Structure

```
arp-spoof-detector/
├── main.c                  # Entry point — interface selection, pcap setup
├── README.md
└── docs/
    ├── project_visual.pdf  # 9-page visual walkthrough of the code
    └── report.pdf          # Full academic research paper (French)
```

### Function Overview

| Function | Purpose |
|---|---|
| `get_local_ip()` | Reads our IP from the working interface via `getifaddrs` |
| `get_local_mac()` | Reads our MAC via `ioctl(SIOCGIFHWADDR)` |
| `mac_addresses_match()` | Compares `ether_shost` vs `arp_sha` — the key security invariant |
| `send_arp_request()` | Builds and sends a broadcast ARP REQUEST via `PF_PACKET SOCK_RAW` |
| `send_syn_and_recv_syn_ack()` | Builds ETH+IP+TCP SYN manually, waits 2s for SYN-ACK/RST |
| `response_half_cycle()` | Full RHC algorithm — probe + collect + decide |
| `callback()` | Called by `pcap_loop()` for every captured ARP packet |
| `add_arp_request()` | Appends a node to the ARP requests linked list |
| `is_reply()` | Finds and removes a matching REQUEST from the list |
| `delete_head()` | Expires REQUEST nodes older than `THRESHOLD_SEC` |
| `add_verifie_relation()` | Adds a verified host to the Host Database |
| `is_verifie_relation()` | Checks if an IP+MAC pair is already verified |
| `csum()` | RFC 1071 internet checksum for IP and TCP headers |
| `verification()` | Deduplicates ARP requests before storing |

---

## Data Structures

### ARP Request List — tracks pending requests

```c
typedef struct arp_request {
    time_t   sec;              // Unix timestamp of capture
    uint8_t  src_ip[4];        // IP of the sender
    uint8_t  dst_ip[4];        // IP being asked about
    uint8_t  src_mac[6];       // MAC of the sender
    struct arp_request *next;  // linked list pointer
} arp_request;
// Node expires after THRESHOLD_SEC = 5 seconds
```

```
HEAD → [req #1] → [req #2] → [req #3] → NULL
         │
    add_arp_request()   on every new REQUEST
    delete_head()       expire after 5 seconds
    is_reply()          remove on matching REPLY
```

### Host Database — verified IP ↔ MAC mappings

```c
typedef struct Verifie_relation {
    uint8_t ip[4];                   // verified IP
    uint8_t mac[6];                  // verified MAC
    char    add_in[30];              // timestamp of verification
    struct  Verifie_relation *next;  // linked list pointer
} Verifie_relation;
// Global head: Verifie_relation *verified_hosts = NULL;
```

### Pseudo Header — TCP checksum only, never sent

```c
struct pseudo_header {
    u_int32_t source_address;  // source IP (network byte order)
    u_int32_t dest_address;    // destination IP
    u_int8_t  placeholder;     // always 0
    u_int8_t  protocol;        // 6 = TCP
    u_int16_t tcp_length;      // TCP header size in bytes
};
```

---

## Requirements

| Dependency | Purpose |
|---|---|
| `gcc` | Compiler (C99) |
| `libpcap-dev` | Packet capture library |
| `Linux kernel ≥ 4.x` | AF_PACKET raw sockets |
| `root / CAP_NET_RAW` | Required for raw socket access |

Install libpcap on Debian/Ubuntu:
```bash
sudo apt update && sudo apt install libpcap-dev
```

---

## Build & Run

```bash
# Clone the repo
git clone https://github.com/yourusername/arp-spoof-detector.git
cd arp-spoof-detector

# Compile
gcc -o arp_detector main.c -lpcap -Wall -Wextra

# Run as root (raw sockets require root)
sudo ./arp_detector
```

**Example session:**
```
Available interfaces:
  1) eth0 (Ethernet)
  2) wlan0 (Wi-Fi)

Choose interface (1-2), 0 = first: 1

[+] Interface : eth0
[+] Local IP  : 192.168.1.99
[+] Listening on eth0 ...

[*] [14:32:01] ARP request: 192.168.1.10 asks for 192.168.1.20
[*] SYN sent to 192.168.1.10 >> aa:bb:cc:11:22:33
[+] SYN-ACK/RST from 192.168.1.10 >> aa:bb:cc:11:22:33
[+] Requester 192.168.1.10 verified.

[-] [14:32:07] Unsolicited ARP reply from 192.168.1.20 - running Response Half Cycle
[RHC] Response Half Cycle detected from 192.168.1.20
[RHC] Probing 192.168.1.20 with ARP request to verify sender...
[ARP] REQUEST sent: who has 192.168.1.20? Tell 192.168.1.99
[RHC] Threshold interval expired. Replies collected: 0
[RHC] SPOOF ALARM: no reply to our ARP probe for 192.168.1.20
[!] [14:32:12] ARP SPOOFING DETECTED from 192.168.1.20
```

---

## Key Constants

```c
#define THRESHOLD_SEC    5      // seconds to collect ARP replies after probe
#define ETH_FRAME_LENGTH 1500   // max ethernet frame size for buffer allocation
#define GROUP_ID         3571   // team ID written into sent ARP packets
#define SPOOF_DETECTED  -2      // return code: spoofing confirmed
#define SPOOF_CLEAN      0      // return code: host is legitimate
```

---

## ⚠️ Important Notes

- **Root required** — raw sockets need `CAP_NET_RAW` capability
- **Linux only** — uses `AF_PACKET`, `SIOCGIFHWADDR`, `SO_RCVTIMEO` (Linux-specific)
- **TCP port 443** — the SYN probe targets HTTPS; modify `tcph->dest` if needed
- **Firewall** — if the target host drops all incoming TCP, the SYN probe will time out (false negative possible). At least one open TCP port is required per assumption 2 of the paper
- **Promiscuous mode** — the interface is opened in promiscuous mode; this may trigger alerts on managed switches

---

## Academic Context

| Field | Details |
|---|---|
| **Institution** | École Supérieure de Technologie — Guelmim (ESTG) |
| **Program** | Réseaux Informatiques et Sécurité — 1ère Année |
| **Author** | Mohamed Soussi |
| **Academic Year** | 2025/2026 |

---

## References

1. **V. Ramachandran & S. Nandi** — *"Detecting ARP Spoofing: An Active Technique"*, Cisco Systems / IIT Guwahati, 2005. *(Primary source)*
2. **W. R. Stevens** — *"TCP/IP Illustrated, Volume 1: The Protocols"*, Addison-Wesley, 1994. ISBN: 0-201-63346-9
3. **D. Plummer** — *"An Ethernet Address Resolution Protocol"*, RFC 826, November 1982. https://www.ietf.org/rfc/rfc0826.txt
4. **D. Bruschi, A. Ornaghi, E. Rosti** — *"S-ARP: a Secure Address Resolution Protocol"*, ACSAC 2003.

---

## License

This project was developed for academic purposes at EST Guelmim.
Feel free to use it for learning and educational purposes.

---

> Mohamed soussi
