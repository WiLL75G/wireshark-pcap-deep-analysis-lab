# Tier 1 Packet Analysis Filter Cheat Sheet

A working reference for the display filters and actions a Tier 1 SOC analyst reaches
for most often. Filters are grouped by **scenario**, because in a real SOC a PCAP
lands on your desk *because something upstream alerted* the alert type tells you
which filters to open with.

Every investigation answers the same three questions:

1. **Who is the aggressor, and who is the target?**
2. **What is the technique, and did it succeed?**
3. **What do I escalate with?** (IOCs: IPs, domains, hashes, URIs)

Filters narrow the traffic. **Interpretation is the analysis.** After every filter,
ask: *what does the presence or absence of these packets tell me about who did
what?*

> Filters below use Wireshark display-filter syntax. To run the same filter from the
> CLI with tshark, wrap it in `-Y`:
> `tshark -r capture.pcap -Y "ip.addr == 10.0.0.5"`

---

## Universal first moves (start every investigation here)

Before filtering, orient yourself. **Statistics → Conversations** shows who is
talking to whom across the whole capture — this is the true first move.

| Filter | What it answers |
|---|---|
| `ip.addr == <suspect_ip>` | All traffic to/from one host scope to the machine of interest |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Every connection attempt (bare SYNs) who is initiating |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1` | Every "I'm listening" reply what answered / what is open |
| `tcp.flags.reset == 1` | Every rejection (RST) what is closed or refused |

**Key action — Follow Stream:** right-click any packet → **Follow → TCP Stream**
(or HTTP Stream). This reconstructs an entire session as readable text. It is the
single most important *action* in Tier 1 packet work it turns scattered packets
into a conversation you can read.

---

## Scenario 1 Port Scan / Reconnaissance (T1046)

**Alert trigger:** IDS "possible port sweep," or one internal/external host touching
many ports.
**Question:** Is one source hitting many destination ports in a short window?

| Filter | Purpose |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.src == <attacker>` | The "knocks" — bare SYNs from the scanner. Many, across different ports = scan |
| `tcp.flags.syn == 1 && tcp.flags.ack == 1 && ip.src == <victim>` | Victim's SYN-ACK replies. **Each one = an open port.** Tells you what the attacker found |
| `tcp.flags.reset == 1` | RST storm from closed ports answering "no" — corroborates the sweep breadth |

**Count unique ports swept (the scan, as one number):**
```
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0 && ip.src==<attacker>" -T fields -e tcp.dstport | Sort-Object -Unique | Measure-Object -Line
```

**The tell:** SYNs fanning out across many destination ports, few SYN-ACKs back,
lots of RSTs. One source → hundreds+ of unique destination ports → one host →
short window.

**Detection takeaway:** A single source initiating SYNs to a large number of
distinct destination ports on one host, with minimal application-layer data and high
RST volume, indicates a TCP port scan (T1046).

---

## Scenario 2 Brute Force Authentication (T1110)

**Alert trigger:** "Multiple failed logins" on SSH (22), RDP (3389), SMB (445),
FTP (21), or a web login.
**Question:** Many auth attempts from one source and did one succeed?

| Filter | Purpose |
|---|---|
| `tcp.port == 22` | SSH traffic (swap `3389` RDP / `445` SMB / `21` FTP as needed) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == <victim> && tcp.port == 22` | Connection attempts to the auth service. A flood from one source = brute force |
| `ip.src == <attacker> && tcp.port == 22` | Isolate the attacker's session to the service, then read behavior |

**"Did they get in?"** SSH is encrypted, so you can't read pass/fail from payload
you read it from **connection behavior**. Failed attempts are short-lived (connect,
reject, teardown, few packets). A success is a connection that **stays open and
transfers noticeably more data**.

→ Open **Statistics → Conversations → TCP**. Look for many tiny near-identical flows
(failures) and **one longer, larger flow** (the success). That one fat conversation
among many thin ones is the compromise.

For cleartext auth protocols (FTP/Telnet) you *can* read success/failure directly
see Scenario 3.

**The tell:** High volume of near-identical short connections, then one that behaves
differently.

**Detection takeaway:** Repeated authentication attempts from a single source to one
service in a short window, followed by a session that deviates in duration/volume,
indicates brute force (T1110) with possible successful compromise.

---

## Scenario 3 Cleartext Credential Exposure (T1040 / weak protocol use)

**Alert trigger:** Audit or IDS flags HTTP, FTP, Telnet, or SNMP carrying auth.
**Question:** Are credentials visible in plaintext on the wire?

| Filter | Purpose |
|---|---|
| `http.request.method == "POST"` | Login forms POST credentials open one and read the form data in cleartext HTTP |
| `ftp` | FTP is fully cleartext — USER and PASS appear right in the Info column |
| `ftp.request.command == "USER" \|\| ftp.request.command == "PASS"` | Isolate just the credential exchange fastest path to the leaked login |
| `telnet` | Telnet sends keystrokes in the clear same idea if in scope |
| `http.authorization` | Catches HTTP Basic Auth (Base64-encoded creds in the header) |

**The move that ties it together:** right-click → **Follow → TCP Stream** (or HTTP
Stream). For cleartext protocols the credentials appear in the stream window in plain
sight. This reconstructs the full login exchange as readable text.

> Note: HTTP Basic Auth credentials are Base64-*encoded*, not encrypted — decode to
> reveal them. Encoding is not protection.

**The tell:** Usernames and passwords readable in the packet bytes or the Follow
Stream window, with no TLS wrapping the session.

**Detection takeaway:** Credentials transmitted over an unencrypted protocol
(HTTP/FTP/Telnet) are recoverable from the capture, confirming a credential-exposure
finding. Often a misconfiguration rather than an attack but a real, escalatable
risk.

---

## The core to memorize

Internalize these seven and you cover the first three scenarios:

| # | Item | Answers |
|---|---|---|
| 1 | `ip.addr == x` | Scope to a host |
| 2 | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | Who is initiating |
| 3 | `tcp.flags.syn == 1 && tcp.flags.ack == 1` | What is open / what answered |
| 4 | `tcp.flags.reset == 1` | What is closed / refused |
| 5 | `tcp.port == 22` (or 3389/445/21) | Target a service |
| 6 | `http.request.method == "POST"` / `ftp` | Find cleartext creds |
| 7 | **Follow TCP Stream** (right-click action) | Reconstruct the session |

Seven things. Everything else is a variation on these.

---

## Handy extras (grow into these)

| Filter | Use |
|---|---|
| `dns` | All DNS queries spot C2 domains, DNS tunneling, exfil |
| `dns.qry.type == 16` | DNS TXT queries abnormal volume/length = DNS exfil (T1048) |
| `http.request` | Every HTTP request URIs, hosts, methods at a glance |
| `frame contains "password"` | Crude keyword hunt across payloads (cleartext only) |
| `ip.dst == <external_ip> && tcp.port == 443` | Suspect C2 over HTTPS port check for HTTP-over-443 evasion |
| `tcp.stream == <n>` | Isolate one TCP conversation by its stream index |

---

## tshark statistics equivalents (no GUI needed)

| Command | GUI equivalent |
|---|---|
| `tshark -r cap.pcap -q -z conv,tcp` | Statistics → Conversations → TCP |
| `tshark -r cap.pcap -q -z io,phs` | Statistics → Protocol Hierarchy |
| `tshark -r cap.pcap -q -z endpoints,ip` | Statistics → Endpoints |
| `capinfos cap.pcap` | File → Capture File Properties |
