# Tier 1 Daily Practice Pattern Recognition Rotation

A weekly drill rotation for the **five recurring Tier 1 triage workflows** that make up
the majority of a real SOC queue. The goal is repetition: run the same workflow enough
times that the pattern is recognised in seconds, not reconstructed from notes.

Each day is one workflow. Each workflow has **steps** (the loop to run) and a
**success criterion** (how you know the pattern is owned, not just familiar). Log
every session: date, data used, time taken, verdict, criterion met yes/no.

Lab reference:
- Attacker (Kali): 192.168.64.15
- Target (Windows 11, JAMES-VM): 192.168.64.17
- Ubuntu / wazuh-manager: 192.168.64.12
- Splunk on macOS host; Universal Forwarder from all three VMs; Wazuh EDR; Sysmon on
  JAMES-VM (EID 1 / 4104 / 22)

The constant across every drill the three questions:
1. Who is the aggressor, and who is the target?
2. What is the technique, and did it succeed?
3. What do I escalate with? (IPs, domains, hashes, users, URIs)

---

## Monday — Brute Force / Password Spray (T1110) Linux + Windows

The highest-frequency real alert. Brute force = many attempts on one account; spray =
few attempts across many accounts. Same triage shape. Drill it on **both** platforms so
you know how it looks in Linux auth logs and in Windows Security logs — the pattern is
the same, the evidence differs.

### Linux side (Ubuntu / wazuh-manager, SSH - 192.168.64.12) VERIFIED WORKING
The attack: `hydra` from Kali (192.168.64.15) against SSH on the Ubuntu box.
Drill convention: **john** = compromise (password `Password123!` is in the wordlist so
hydra succeeds), **mary** = pure fail (password not in the wordlist).

**Where it shows up:** `/var/log/auth.log` → Splunk as `sourcetype=linux_secure`,
`index=main`.
- Failure line: `Failed password for <user> from <ip> port <n> ssh2`
- Failure (invalid user): `Failed password for invalid user <user> from <ip>`
- **Success line:** `Accepted password for <user> from <ip> port <n> ssh2`

> **Build quirk (locked):** this Splunk build's `linux_secure` auto-extraction does NOT
> populate `user` / `src_ip`. You MUST add a `rex` to extract them, or `stats by user,
> src_ip` returns nothing.

**The one-glance breach detector (verified working search):**
```spl
index=main host=wazuh-manager sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "for (?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| eval outcome=if(match(_raw,"Accepted"),"SUCCESS","FAIL")
| stats count by user, src_ip, outcome
```
Returns: **mary = FAIL only** (brute force, no breach) vs **john = FAIL + 1 SUCCESS**
(compromise), both from 192.168.64.15. The single SUCCESS row is the whole point.

**Find compromises only:**
```spl
index=main host=wazuh-manager sourcetype=linux_secure "Accepted password"
| rex "for (?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, user, src_ip
```

**Pivot after a compromise** — what did the session do?
```spl
index=main host=wazuh-manager sourcetype=linux_secure ("sudo" OR "session opened" OR "useradd")
| table _time, _raw
```
Captures sudo escalation (with the exact `COMMAND=` run), new users, and cron.

### Windows side (JAMES-VM — 192.168.64.17) — pipeline VERIFIED
**Where it shows up:** `sourcetype=WinEventLog:Security` in Splunk. Unlike Linux,
Windows extracts fields **natively** — `Account_Name` and `Source_Network_Address`
populate without a rex.
- Failure: **EventCode 4625** (failed logon) — read the logon type and account.
- **Success:** **EventCode 4624** (successful logon) after the burst.
- Process activity: **4688** (process creation, high volume). Privilege: **4672**.

**Verified working search:**
```spl
index=* host=JAMES-VM sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Source_Network_Address
```

> **Verified state + hardening finding (Jul 12 2026):** the Windows Security pipeline is
> confirmed and carries 4625/4624/4688/4672 with native field extraction. Real 4625
> attacker data exists (failed logons for `socdemo` and `-` from 192.168.64.15), so
> Monday-Windows is drillable now — just thin.
>
> Generating a *fresh, richer* Windows brute force proved constrained, and that
> constraint is itself a defender's finding worth knowing:
> - **SMB (445) is open but hardened** `signing:True` on Win11 Build 26100. hydra and
>   netexec both time out at the NETBIOS/transport layer; no clean failed-logon
>   telemetry is produced. Modern Windows resists SMB brute force by design.
> - **RDP (3389) does not bind** even after enabling the service, firewall rule, and
>   registry keys (`fDenyTSConnections=0`, `fEnableWinStation=1`, `PortNumber=3389`,
>   `TermService`+`UmRdpService` both running, full reboot). `qwinsta` is absent on this
>   build — the RDP listener components appear incomplete on Build 26100. Deeper fix
>   (Windows Features / DISM) needed; not worth chasing mid-drill.
>
> **Takeaway:** "why is this Windows box hard to attack?" → "because it's hardened by
> default." Drill Monday-Windows on the captured 4625 data. If you want fresh telemetry
> later, the cleaner path is a local-account logon-failure generator or fixing the RDP
> role, not fighting SMB signing.

**Success when:** on *either* platform you can trace one attacker from first failure →
success → post-login action as a single story, and you can name the difference in
evidence: Linux = `auth.log` Failed/Accepted lines (needs rex), Windows = 4625 → 4624
(native fields).

---

## Tuesday — Phishing Email Triage (T1566)

One of the most common Tier 1 tasks. The email is reported or flagged; you decide how
dangerous it is and how far it spread.

**Workflow:**
1. Header analysis: sender, reply-to, SPF/DKIM/DMARC results, sending IP.
2. Payload: examine the URL or attachment (detonate/inspect safely — never click
   live). Extract the destination domain / file hash.
3. IOC extraction: sender address, sending IP, URL/domain, attachment hash.
4. Scope: **who else received it?** Search mail logs for the same sender/subject/URL.
5. Verdict: benign, spam, or malicious → escalate + block IOCs.

**Success when:** you can produce a full IOC set and answer "how many users were
targeted / clicked" scope is the part juniors forget.

---

## Wednesday — Host Log Triage, Windows AND Linux (T1078 / T1059 / persistence)

Pattern-heavy and recurring. The skill is knowing what each log source records and
which combinations tell a story. Windows speaks in **EventCodes**; Linux speaks in
**log-file text**. Drill both — an MSSP box is a mix of both.

### Side A Windows Event Logs (JAMES-VM)

**Key EventCodes to know cold:**
- 4625 failed logon / 4624 successful logon (+ logon type)
- 4688 process creation
- 4720 account created / 4728 / 4732 group membership change
- 4672 special privileges assigned
- 7045 new service installed

**Workflow:**
1. Narrow to the host + time window.
2. Aggregate the relevant EventCode: `stats count by ...`.
3. Read the logon **type** (Type 3 network, Type 10 RDP) — it changes the meaning.
4. Pivot: tie an account creation (4720) or privilege grant (4672) back to who did it
   and whether it was authorized/ticketed.
5. Verdict: normal admin activity or malicious?

**Success when:** you can narrate an EventCode sequence as a story ("network logon →
new service → privilege grant = suspicious") without a lookup.

### Side B Linux Log Analysis (Ubuntu / wazuh-manager)

Linux security-relevant events live in text log files, not EventCodes. Know the files
and the lines:

| Log file | What it records | Lines to know |
|---|---|---|
| `/var/log/auth.log` | Auth, sudo, SSH | `Failed/Accepted password`, `sudo: ... COMMAND=`, `session opened for user root` |
| `/var/log/syslog` | General system | service starts/stops, cron |
| `/var/log/audit/audit.log` | auditd (if enabled) | syscall/file-access events |
| `.bash_history` | Command history | what a user actually typed |

**Verified working search (Jul 12 2026)** confirmed to capture sudo escalation with
the exact command, cron, and new-user activity in `sourcetype=linux_secure`:
```spl
index=main host=wazuh-manager sourcetype=linux_secure ("sudo" OR "useradd" OR "session opened")
| table _time, _raw
```
Real output seen: `sudo: ... USER=root ; COMMAND=/usr/bin/passwd john` (privilege
escalation with the exact command captured), `CRON session opened for user root`
(scheduled task), `sshd session opened for user john` (the login after a compromise).

**Workflow:**
1. Narrow: `index=main host=wazuh-manager sourcetype=linux_secure` + time window.
2. Aggregate: `stats count by user, src_ip` on auth events (add a `rex` for fields
   same build quirk as Monday).
3. Watch for privilege escalation: `sudo` to root (the `COMMAND=` line shows exactly
   what ran), `session opened for user root`, new user creation (`useradd`), unexpected
   cron entries (persistence).
4. Pivot: after a suspicious login, what commands ran? (auth.log sudo lines,
   process logs, `.bash_history`).
5. Verdict: normal admin, or malicious activity / persistence?

**Success when:** you can read a Linux auth.log sequence and narrate the story
("SSH accepted → sudo to root → useradd → new cron job = compromise + persistence")
and you can name, for any given event, whether you'd find the evidence in a Windows
EventCode or a Linux log line.

### The cross-platform takeaway
Same attacker goals (log in, escalate, persist) show up as **4624 → 4672 → 7045** on
Windows and **Accepted password → sudo root → cron/useradd** on Linux. Learn to read
the same story in both dialects.

---

## Thursday — EDR / Endpoint Alert Triage (Wazuh; T1059 / T1204 / persistence)

One of the highest-volume real alert types. An endpoint detection fires; you decide if
it executed and whether the host is compromised.

**Workflow:**
1. Read the alert: what rule fired, on which host, what process/file.
2. Context: parent-child process chain — what launched it? (Sysmon EID 1)
3. Decode: if PowerShell, pull the script block (EID 4104) and deobfuscate any encoded
   command.
4. Determine execution + impact: did it run, what did it touch, was it contained?
5. Verdict: benign admin action, or malicious execution → isolate host?

**Success when:** you can read a parent-child chain and a script block and say whether
it's malicious, plus name the host to isolate.

---

## Friday — Threat Hunting (proactive; multi-technique)

Not reactive alert triage a hypothesis-driven hunt. Different loop, worth its own
rep because it builds the "find it before it alerts" instinct.

**Workflow:**
1. Hypothesis: pick a technique ("beaconing to external IP," "encoded PowerShell,"
   "lateral movement via Type 3 logons").
2. Search: build the query that would surface it if present.
3. Aggregate + baseline: `stats count by ...`; compare to what normal looks like.
4. Pivot on anything anomalous across other sourcetypes.
5. Verdict: nothing found (document the hunt), or a lead → convert to an incident.

**Success when:** you can go from a hypothesis to a query to a verdict without a
template, and you document a "found nothing" hunt as rigorously as a hit.

---

## Weekend — Cold Reps (the real test)

Work data you did **not** generate. The NetSupport RAT PCAP, then fresh captures from
Malware-Traffic-Analysis.net. Timed, no notes, no hints.

**Success when:** you can walk a stranger's capture or log set end-to-end and produce
aggressor/target, technique, did-it-succeed verdict, and a full IOC table in one
sitting. This is what a practical interview looks like.

---

## How to run the rotation

- **One workflow per day.** Consistency beats intensity 30 focused minutes daily
  beats a five-hour weekend cram.
- **Log every session** (date / data / time / verdict / criterion met). The log is
  both your progress tracker and a portfolio artifact ("here's how I trained").
- **Re-run any workflow you couldn't complete without notes.** A pattern is owned only
  when the success criterion is met cold.
- **Rotate the underlying data** so you're not memorising one capture. Re-generate
  attacks with fresh IPs/timing to keep the pattern general, not the specific file.

---

## Why these five

| Day | Workflow | Why it's daily-worthy |
|---|---|---|
| Mon | Brute force / spray | Highest-frequency auth alert |
| Tue | Phishing triage | Most common Tier 1 task |
| Wed | Windows event triage | Pattern-heavy, underpins many alerts |
| Thu | EDR alert triage | Highest-volume endpoint alert type |
| Fri | Threat hunting | Builds proactive "find it first" instinct |
| Sat/Sun | Cold reps | Proves the patterns transfer |

Reactive triage (Mon–Thu) + proactive hunting (Fri) + transfer test (weekend) = the
full Tier 1 rhythm in one week.
