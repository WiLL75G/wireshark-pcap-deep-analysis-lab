# Tier 1 Practice Drills — Pattern Recognition Checklist

A structured practice plan for building **Tier 1 pattern recognition** in a home lab.
The goal is not "I did it once" — it's "I recognise this in seconds." Each drill has a
**success criterion**: you've locked the pattern in when you can meet it *without
notes*.

Work these against real lab artifacts. Repetition on a small number of clean captures
beats reading about many.

Lab reference:
- Attacker (Kali): 192.168.64.15
- Target (Windows 11, JAMES-VM): 192.168.64.17
- Ubuntu / wazuh-manager: 192.168.64.12
- Splunk on macOS host, Universal Forwarder from all three VMs

---

## Tier A — Drill on data you already have

### Drill 1 — Port scan, cold and timed
- **Do:** Open `portscan.pcap` with no notes. Answer the three questions — who is the
  aggressor, what is open, is this recon — in under 5 minutes.
- **Repeat:** 3 times across 3 different days.
- **Success when:** you identify open ports (135/139/445), confirm the single-source
  fan-out, and state the verdict without reaching for a cheat-sheet.

### Drill 2 — Brute force: the fail → success → action pivot
- **Do:** In Splunk, start from the failed logons (4625), find the success (4624) that
  follows the burst, then pivot to what that session did *after* login.
- **Data:** your SSH brute-force set (failures + successes from 192.168.64.15).
- **Success when:** you can trace one attacker from first failure to compromise to
  post-login activity as a single story — this is the most important pattern in the
  job.

### Drill 3 — DNS anomaly reading
- **Do:** Review your DNS-tunneling data. Distinguish abnormal query length / TXT
  volume / interval regularity from normal DNS.
- **Success when:** you can point to *why* a query pattern is abnormal, not just that
  it "looks weird."

---

## Tier B — Skills named but not yet drilled

### Drill 4 — Follow Stream until it's reflex
- **Do:** Generate a cleartext FTP or HTTP login between VMs, capture it, and
  reconstruct the credentials via right-click → Follow → TCP/HTTP Stream.
- **Success when:** "right-click → Follow → read the creds" is automatic and you can
  find the username/password in the stream in under a minute.

### Drill 5 — Export Objects (pull a file from a PCAP)
- **Do:** Transfer a file over HTTP between two VMs, capture it, then extract it from
  the PCAP (File → Export Objects → HTTP) and hash it (`Get-FileHash`).
- **Success when:** you can go from raw PCAP to an extracted file and a hash ready for
  VirusTotal — this is the malware-delivery triage skill.

### Drill 6 — The `stats` aggregation reflex (Splunk)
- **Do:** On your brute-force data, practice shaping with aggregation:
  `stats count by src_ip`, `stats dc(dest_port) by src_ip`,
  `bucket _time span=1m | stats count by _time` for beacon regularity.
- **Success when:** your instinct on any new search is to aggregate *before* reading
  raw events — you see patterns in counts, not by scrolling logs.

### Drill 7 — Baseline vs anomaly
- **Do:** Search normal auth/network traffic on a quiet period and note its shape.
  Then run your attack data and observe how it deviates.
- **Success when:** you can describe "normal" for a host well enough that "abnormal"
  jumps out immediately.

### Drill 8 — Timeline reconstruction
- **Do:** Take one attack (e.g. the brute force) and build a minute-by-minute timeline
  from first failed login → compromise → post-exploit action.
- **Success when:** you produce a clean chronological timeline a Tier 2 analyst could
  act on without re-doing your work.

### Drill 9 — False-positive triage
- **Do:** Deliberately generate benign-but-suspicious-looking traffic — a vuln scan
  you "own," or a service account authenticating repeatedly — and practice recognising
  it as benign fast.
- **Success when:** you can dismiss a benign pattern with a stated reason quickly,
  instead of over-investigating noise. Half the job is dismissing noise correctly.

---

## Tier C — The real test

### Drill 10 — Cold PCAP, no hints, timed
- **Do:** Work PCAPs you did **not** generate. Start with the NetSupport RAT capture,
  then pull 2–3 more from Malware-Traffic-Analysis.net. Work each cold and timed: no
  notes, no hints.
- **For each, produce:** aggressor + target, technique, did-it-succeed verdict, and a
  full IOC set (IPs, domains, hashes, URIs).
- **Success when:** you can walk a stranger's capture end-to-end and produce an IOC
  table in one sitting. This is what a practical interview looks like.

---

## How to run the program

1. **Tier A first** — lock the patterns on data you understand.
2. **Tier B next** — fill the skill gaps (Follow Stream, Export Objects, stats,
   baseline, timeline, FP triage).
3. **Tier C last** — prove it transfers to traffic you've never seen.

Log each drill: date, capture used, time taken, verdict, whether you met the success
criterion. Re-run any drill you couldn't complete without notes. A pattern is only
"owned" when the success criterion is met cold.

---

## The three questions (the constant across every drill)

1. **Who is the aggressor, and who is the target?**
2. **What is the technique, and did it succeed?**
3. **What do I escalate with?** (IPs, domains, hashes, URIs)

Every drill is practice at answering these faster and more reliably.
