# Environment Setup — Capture Host (JAMES-VM)

This document records how the packet-capture environment was built on the target
Windows host for the `wireshark-pcap-deep-analysis-lab`. Capture is performed
**victim-side** — on the host receiving the attack traffic — which reflects how a
real sensor or endpoint sees traffic, rather than capturing from the attacker box.

## Host details

| Field | Value |
|---|---|
| Hostname | JAMES-VM |
| OS | Windows 11 (25H2, build 26200) |
| Architecture | arm64 (Apple Silicon under UTM) |
| IP address | 192.168.64.17 |
| Subnet | 192.168.64.0/24 |
| Role in lab | Capture host / attack target |
| Capture tooling | Wireshark 4.6.7 + Npcap |

---

## Step 1 — Install Wireshark (winget)

```powershell
winget install WiresharkFoundation.Wireshark
```

Installed **Wireshark 4.6.7** (arm64 build, correct for Windows 11 on Apple
Silicon). This provides the GUI plus the CLI tooling used throughout the lab:
`tshark`, `capinfos`, and `dumpcap`.

---

## Step 2 — Verify capture capability (and find the gotcha)

```powershell
tshark -D
```

**Result:**

```
tshark: Unable to load Npcap (wpcap.dll); you will not be able to
capture packets.
1. etwdump (Event Tracing for Windows (ETW) reader)
```

The winget package installed Wireshark but its bundled **Npcap** sub-installer did
not run, so the Windows packet-capture driver was absent. Only the ETW reader was
listed — no real network interfaces.

> **Key lesson:** Wireshark can *read* existing PCAPs without Npcap, but it
> **cannot capture live traffic** without it. Npcap is the Windows packet-capture
> driver (successor to WinPcap). The missing-driver condition is diagnosable
> directly from the `tshark -D` error rather than by guessing.

---

## Step 3 — Install Npcap separately

Downloaded the free installer from **https://npcap.com** and ran it with defaults:

- WinPcap API-compatible Mode: **enabled** (default)
- Support raw 802.11 traffic: **not selected** (not needed for wired capture)

---

## Step 4 — Add Wireshark to the system PATH

Run from an **elevated** PowerShell:

```powershell
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Wireshark", "Machine")
```

This lets `tshark`, `capinfos`, and `dumpcap` resolve from any directory without
the full path.

> **Key lesson:** PATH changes only apply to **new** shell sessions. The existing
> PowerShell window must be closed and reopened for the change to take effect.

---

## Step 5 — Re-verify interfaces

Open a fresh PowerShell:

```powershell
tshark -D
```

**Result (real interfaces now listed):**

```
1. \Device\NPF_{6F13502F-...} (Local Area Connection* 8)
2. \Device\NPF_{94AAA5B3-...} (Local Area Connection* 7)
3. \Device\NPF_{494C4BA1-...} (Local Area Connection* 6)
4. \Device\NPF_{F091B4AD-7870-40D0-833F-B1F638C1409B} (Ethernet)
5. \Device\NPF_Loopback (Adapter for loopback traffic capture)
6. etwdump (Event Tracing for Windows (ETW) reader)
```

---

## Step 6 — Identify the correct capture interface

Do not assume by name — confirm by IP:

```powershell
ipconfig
```

The **Ethernet** adapter held `192.168.64.17`, mapping to **interface 4** in the
`tshark -D` list. The `Local Area Connection*` adapters are virtual/disconnected
and were disregarded.

---

## Step 7 — Live interface test

Confirm interface 4 actually sees traffic before relying on it for a real capture:

```powershell
tshark -i 4 -a duration:5
```

Captured 29 packets in 5 seconds (background host traffic — Splunk Universal
Forwarder chatter and gateway probes), confirming the interface was live and
correctly bound.

---

## Environment ready

With Npcap installed, PATH configured, and interface 4 confirmed live, the host is
ready for scoped per-scenario captures, e.g.:

```powershell
tshark -i 4 -f "host 192.168.64.15 and host 192.168.64.17" -w portscan.pcap
```

The BPF capture filter (`-f`) scopes the capture to only attacker↔victim traffic
so each scenario PCAP is a clean, self-contained artifact.

---

## Troubleshooting notes

| Symptom | Cause | Fix |
|---|---|---|
| `Unable to load Npcap (wpcap.dll)` | Npcap driver not installed | Install Npcap from npcap.com |
| Only `etwdump` in `tshark -D` | No capture driver bound | Install Npcap |
| `tshark` not recognized | Wireshark not on PATH | Add `C:\Program Files\Wireshark` to PATH, reopen shell |
| PATH change not applied | Old shell session | Close and reopen PowerShell |
| Empty PCAP after capture | Wrong interface selected | Confirm interface by matching IP in `ipconfig` |
