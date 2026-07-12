# Port Scan Analysis (T1046)

Reconstructing a TCP SYN scan from a raw packet capture alone, then tying the finding
back to detection logic.

| Field | Value |
|---|---|
| Technique | T1046 — Network Service Discovery |
| Attacker | Kali Linux, 192.168.64.15 |
| Target | Windows 11 (JAMES-VM), 192.168.64.17 |
| Capture | `portscan.pcap` 4,136 packets, 372 kB, ~90s window |
| Detection tie-in | Suricata sid 1000001 |

---

## Attack

A TCP SYN ("half-open") scan against the target's first 1,000 ports:

```
sudo nmap -sS -p 1-1000 192.168.64.17
```

A SYN scan never completes the TCP handshake. It sends SYN, reads the reply, then
sends RST instead of ACK enough to learn a port's state without opening a full,
loggable connection. Ground truth from nmap: three open ports (135, 139, 445), 997
closed, scan completed in 1.76s.

## Capture setup

Captured victim-side on JAMES-VM (the target always sees traffic addressed to it),
scoped with a BPF capture filter so only attacker↔victim traffic hit disk:

```
tshark -i 4 -f "host 192.168.64.15 and host 192.168.64.17" -w portscan.pcap
```

`capinfos` confirms provenance: 4,136 packets, average packet size 57 bytes. That tiny
average is itself a fingerprint a capture that is almost entirely 54–66 byte control
packets with no payload is scanning, not communication.

## Display filters used and what the packets revealed

**Open ports — the victim's SYN-ACK replies:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.src == 192.168.64.17
```
Every SYN-ACK from the target is a port answering "yes, I'm listening." Result: source
ports 135, 139, 445 the Windows SMB/RPC stack. This matched nmap's ground truth
exactly, determined from raw packets with no scanner output.

**The attacker's probes bare SYNs:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == 192.168.64.15
```
2,122 SYNs from the attacker more than 1,000 because nmap retransmits to ports that
stay silent. (Raw SYN count is not the same as port count, due to retransmission.)

**Unique ports swept the detection number:**
```
tshark -r portscan.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==192.168.64.15" -T fields -e tcp.dstport | sort -u | wc -l
```
1,000 distinct destination ports from one source against one host in ~90 seconds. No
user or legitimate application behaves this way. This number *is* the scan.

**Protocol hierarchy:** TCP dominates with effectively nothing above it no
application-layer data. Pure control plane confirms reconnaissance, not usage.

## Detection takeaway

A single source initiating SYN connections to a large number of distinct destination
ports on one host within a short window, with minimal application-layer data and a high
volume of RST responses, indicates a TCP port scan (T1046).

This maps to **Suricata sid 1000001**, which alerts on the connection fan-out
threshold. Reading SYN-ACKs proves what is open; counting SYNs-to-many-ports proves
someone is scanning — the fan-out is the alert.

## The reusable pattern

1. Verify the capture (`capinfos`).
2. Find what is open victim SYN-ACKs.
3. Find the knocking attacker bare SYNs.
4. Prove the fan-out count unique destination ports.
5. Confirm it is recon protocol hierarchy is all TCP, no payload.
