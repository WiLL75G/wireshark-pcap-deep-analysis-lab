# Wireshark PCAP Deep Analysis Lab

Packet level PCAP forensics. Reconstructing attacks from raw capture alone, with no SIEM safety net, then tying each finding back to SIEM and IDS detection logic. Built to close the packet analysis gap in a detection engineering portfolio.

Author: William Gokah ([@WiLL75G](https://github.com/WiLL75G)) . Detection engineer and SOC analyst

---

## What this lab demonstrates

Reading traffic at the packet level and answering the three questions a Tier 1 analyst asks of any capture. Who is the aggressor. What is the technique and did it succeed. What do I escalate with. Each scenario is captured victim side, the way a real sensor or endpoint sees traffic, analysed from the PCAP alone, then mapped back to a detection.

## Lab topology

| Host | Role | IP |
|---|---|---|
| Kali Linux | Attacker | 192.168.64.15 |
| Ubuntu Server (wazuh-manager) | Target and Linux telemetry | 192.168.64.12 |
| Windows 11 (JAMES-VM) | Target and capture host | 192.168.64.17 |
| macOS host | Splunk indexer and Wazuh manager (Docker) | n/a |

Capture tooling: Wireshark and tshark, captured victim side. SIEM: Splunk. EDR: Wazuh. IDS: Suricata.

## MITRE ATT&CK coverage

| Technique | Scenario | Status |
|---|---|---|
| T1046 Network Service Discovery | 01 Port scan | Complete |
| T1110 Brute Force | 02 SSH brute force | Complete |
| T1040 Cleartext credentials | 03 Cleartext credentials | Planned |
| T1048 and T1071 Exfil and C2 | 04 DNS exfiltration | Planned |

## Repository contents

| Document | Purpose | Status |
|---|---|---|
| [SETUP.md](SETUP.md) | Capture environment build, Wireshark, tshark, and Npcap on Windows | Complete |
| [docs/TIER1-PLAYBOOK.md](docs/TIER1-PLAYBOOK.md) | Packet analysis scenario strategy | Complete |
| [docs/FILTERS.md](docs/FILTERS.md) | Tier 1 Wireshark and tshark filter kit | Complete |
| [docs/SPLUNK-TIER1-PLAYBOOK.md](docs/SPLUNK-TIER1-PLAYBOOK.md) | Splunk triage mental model | Complete |
| [docs/TIER1-DRILLS.md](docs/TIER1-DRILLS.md) | Pattern recognition practice program | Complete |
| [docs/TIER1-DAILY-PRACTICE.md](docs/TIER1-DAILY-PRACTICE.md) | Verified weekly drill rotation, tested against live data | Complete |
| [analysis/01-portscan.md](analysis/01-portscan.md) | Port scan PCAP analysis, T1046 | Complete |
| [analysis/02-ssh-bruteforce.md](analysis/02-ssh-bruteforce.md) | SSH brute force PCAP analysis, T1110 | Complete |
| analysis/03-cleartext-creds.md | Cleartext credential exposure, T1040 | Planned |
| analysis/04-dns-exfil.md | DNS exfiltration, T1048 | Planned |

## Key findings so far

Scenario 01, port scan. Determined three open ports (135, 139, and 445) from raw packets alone by reading the victim SYN ACK replies, matching nmap ground truth with no scanner output. Confirmed a single source sweeping 1000 distinct destination ports, the fan out that maps to Suricata sid 1000001.

Scenario 02, SSH brute force. Captured a hydra attack victim side and confirmed the brute force from repeated encrypted SSH negotiations. Because SSH is encrypted, the packets flag the attack but cannot prove the breach, so the compromise was confirmed by correlating with the Splunk auth log. Packets flag the anomaly, logs confirm the compromise. Maps to Suricata sid 1000002 and the Splunk linux_secure detection.

## Status

Active build. Scenarios 01 and 02 are complete along with the full Tier 1 analysis and drill documentation. Scenarios 03 and 04 are in progress.
