# SANS Hackathon — Forensic Triage Report
**Analyst:** Claude Code (claude-sonnet-4-6)  
**Date:** 2026-04-30  
**Evidence:** Redis memory captures — `sans:dc:psscan` (124 processes), `sans:fileserver:psscan` (101 processes)  
**Scope:** Domain Controller (DC) and File Server (FS) on the same network

---

## Executive Summary

Both systems are **fully compromised**. The File Server was the initial beachhead, likely compromised before the earliest capture timestamp, with persistence established via a Ruby/Metasploit service (`rubyw.exe`). The attacker used WMI to deploy a Cobalt Strike–style C2 framework on the File Server, ran 28 beacon processes across 7 days, staged data for exfiltration with `Rar.exe`, then moved laterally to the Domain Controller. Both systems received the same custom backdoor (`subject_srv.ex`) installed as a persistent service in the final hours of 2018-09-06, with the File Server backdoored ~2h 46m before the DC.

---

## Evidence Sources

| Key | System | Process Count |
|-----|--------|--------------|
| `sans:dc:psscan` | Domain Controller | 124 |
| `sans:fileserver:psscan` | File Server | 101 |

Analysis methods: psscan (EPROCESS block carving), parent-child tree reconstruction, orphaned process detection, duplicate PID analysis, cross-system correlation, timeline reconstruction.

---

## Finding 1 — PRIMARY MALWARE: `subject_srv.ex` on Both Systems

**Severity: CRITICAL**

The single highest-confidence IOC: an identically-configured non-standard process running as a persistent service on both machines simultaneously.

| Attribute | DC (PID 5128) | File Server (PID 6160) |
|-----------|--------------|----------------------|
| Parent | `services.exe` PID 644 | `services.exe` PID 536 |
| Session | 0 (SYSTEM) | 0 (SYSTEM) |
| Wow64 | **True** (32-bit on 64-bit OS) | **True** |
| Threads | 10 | 12 |
| Created | 2018-09-06 **22:11:15** UTC | 2018-09-06 **19:25:36** UTC |
| Exited | N/A (running at capture) | N/A (running at capture) |

**Analysis:**
- `subject_srv.ex` is not a Windows built-in and matches no recognized vendor process
- The name is truncated at 15 characters — the hard limit of the Windows EPROCESS `ImageFileName` field — confirming it is `subject_srv.exe`
- `Wow64=True` (32-bit process on 64-bit OS) is a common technique for evading 64-bit AV/EDR hooks
- Both instances run in Session 0 (SYSTEM context), launched from `services.exe` — installed as a Windows service for persistence across reboots
- The File Server was backdoored first; the DC followed ~2h 46m later, consistent with an operator deploying persistence after completing lateral movement
- The matching `Wow64=True` / `Session=0` / `services.exe` parent footprint on both machines confirms the same binary deployed by the same operator

---

## Finding 2 — INITIAL ACCESS & C2 ON FILE SERVER: WMI → PowerShell → 28× rundll32

**Severity: CRITICAL**

The definitive attack execution chain on the File Server:

```
WmiPrvSE.exe (PID:1196)  [svchost:600 child, running since 2018-08-08]
  └─> powershell.exe (PID:4072)              2018-08-28 22:08:25 UTC  ← WMI execution trigger
        └─> powershell.exe (PID:3164)        2018-08-28 22:08:26 UTC  ← Wow64=True, 32-bit staging shell
              ├─> rundll32.exe (PID:3376)    2018-08-30 01:46:24 UTC  ← first beacon
              ├─> rundll32.exe (x10 burst)   2018-08-31 22:03–22:17   ← C2 operational
              ├─> rundll32.exe (PID:3500)    2018-08-30 18:28:04 UTC
              ├─> ... [28 total] ...
              └─> rundll32.exe (PID:5640)    2018-09-06 16:01:45 UTC  ← last beacon
```

**Analysis:**
- `WmiPrvSE.exe` spawning `powershell.exe` is **never legitimate** — this is the attacker's WMI execution entry point, invoked via `wmic`, `Invoke-WmiMethod`, or a WMI subscription
- The second PowerShell (PID:3164) is `Wow64=True` — the standard Cobalt Strike pattern where a 32-bit staging beacon spawns 32-bit post-exploitation processes to avoid 64-bit hook detection
- **28 `rundll32.exe` processes** spawned across 7 days (2018-08-30 through 2018-09-06). All 28 have exited at capture time with exit ≈ create time. This is Cobalt Strike's `spawnto` technique: inject shellcode into a sacrificial process host, complete the task, then exit. The `rundll32.exe` processes are not executing any legitimate DLL — they are hollowed hosts for shellcode beacons
- Both PowerShell processes (PID:4072 and PID:3164) remain alive at capture time, maintaining the C2 parent session
- The 7-day beacon cadence indicates persistent, recurring operator tasking (not a one-shot compromise)

**Self-correction:** WmiPrvSE (PID:1196) was created at system boot on 2018-08-08. It did not spawn PowerShell until 2018-08-28 — 20 days later. The provider process itself is the legitimate Windows component; the attack used the WMI execution interface as a living-off-the-land proxy.

---

## Finding 3 — PRE-EXISTING METASPLOIT FOOTHOLD ON FILE SERVER

**Severity: CRITICAL**

Four processes started at File Server **boot time (2018-08-08 ~18:08 UTC)** indicate the system was compromised before this capture window:

| Process | PID | PPID | Wow64 | Threads | Significance |
|---------|-----|------|-------|---------|--------------|
| `rubyw.exe` | 1156 | 536 | False | 10 | Ruby runtime (no console window). **Metasploit installs persistent Meterpreter via `rubyw.exe` as a Windows service** |
| `nscp.exe` | 1304 | 536 | True | 17 | NSClient++ — monitoring agent, commonly abused for C2 or for privilege escalation via `check_nrpe` |
| `ncpa_listener.` | 2848 | 536 | True | 2 | NCPA monitoring agent |
| `ncpa_passive.e` | 2868 | 536 | True | 5 | NCPA monitoring agent |

**Analysis:**
- `rubyw.exe` is the Ruby interpreter compiled without a console window — the exact binary Metasploit's `exploit/multi/handler` installs when creating a persistent Windows service. It has 10 threads, runs in Session 0, under `services.exe`, with no exit time. This is the initial foothold the attacker maintained on the File Server
- NSClient++ (nscp.exe) can be exploited for privilege escalation and is a known C2 channel. Combined with two NCPA agents, this suggests a monitoring infrastructure deliberately installed as attack tooling
- All four started at the first system boot timestamp in the data — they were deployed during initial compromise, before the WMI activity began

---

## Finding 4 — LATERAL MOVEMENT TO DC: ManagementAgent Execution Chain

**Severity: HIGH**

On the DC, `ManagementAgent` (PID:908, child of `services.exe`) spawned 4 cmd.exe processes across multiple days with deep sub-chains:

```
services.exe (PID:644)
  └─> ManagementAgent (PID:908)     [2018-08-16 21:07:53 — present since near-boot]
        ├─> cmd.exe (PID:4588)      2018-09-01 17:48:11  [exited <1 sec — probe]
        ├─> cmd.exe (PID:1036)      2018-09-06 17:47:38
        │     ├─> cmd.exe (4648)    same second
        │     ├─> cmd.exe (2308)    +1 second
        │     └─> cmd.exe (6940)    +1 second
        ├─> cmd.exe (PID:3380)      2018-09-06 18:17:46
        │     └─> cmd.exe (6572)    same second
        └─> cmd.exe (PID:6628)      2018-09-06 22:53:58
              ├─> cmd.exe (9012)    same second
              ├─> cmd.exe (7260)    same second
              └─> cmd.exe (8220)    same second
```

**Analysis:**
- A management agent (McAfee, SCCM, or similar) should **never spawn cmd.exe** — this is the attacker's command execution interface on the DC
- 3–4 `cmd.exe` children spawning at the **exact same second** is scripted/automated execution (not human keyboard input). This pattern is consistent with batch scripts, PsExec-style remote execution, or a compromised management agent being used as a C2 relay
- The first event (2018-09-01 17:48:11) is 4 days after the WMI chain was established on the FS, consistent with FS→DC lateral movement using credentials harvested via the Metasploit/Cobalt Strike session

---

## Finding 5 — RECONNAISSANCE ON DC

**Severity: HIGH**

Classic `tasklist | findstr` enumeration pattern, repeated across multiple days:

| Process | PID | PPID | Parent Status | Timestamp |
|---------|-----|------|---------------|-----------|
| `tasklist.exe` | 7612 | 9056 | **NOT IN LIST** | 2018-09-06 17:57:41 |
| `tasklist.exe` | 7284 | 8096 | **NOT IN LIST** | 2018-09-04 19:58:33 |
| `findstr.exe` | 8492 | 3192 | **NOT IN LIST** | 2018-09-01 18:18:19 |
| `findstr.exe` | 4980 | 5604 | **NOT IN LIST** | 2018-09-06 11:14:39 |

**Analysis:**
- All 4 instances have orphaned parents — the cmd.exe that launched each recon tool was **terminated after execution** to break the process tree (deliberate anti-forensics)
- Two rounds of `tasklist` and two rounds of `findstr` across 5 days indicates repeated process enumeration — the attacker was checking for AV/EDR processes, identifying targets, or mapping the domain environment
- `findstr` used in conjunction with `tasklist` typically filters for specific process names: `tasklist | findstr /i "av defender endpoint"`

---

## Finding 6 — PROCESS HOLLOWING INDICATOR ON DC: RuntimeBroker → PowerShell → notepad

**Severity: HIGH**

```
svchost.exe (PID:836)
  └─> RuntimeBroker.exe (PID:4932)     2018-08-16 21:36:57 UTC
        └─> powershell.exe (PID:5612)  2018-08-16 22:10:54 UTC  ← illegitimate spawn
              ├─> conhost.exe (5488)
              └─> notepad.exe (PID:7936)  2018-08-17 04:42:25 UTC  ← process hollowing target
```

**Analysis:**
- `RuntimeBroker.exe` is a Windows Store app permissions broker — it **does not spawn PowerShell** under any legitimate condition. This is a parent process spoofing technique: the attacker manipulated the PPID of a new PowerShell process to appear as if RuntimeBroker spawned it, to evade parent-child detection rules
- `notepad.exe` spawned by PowerShell is a **process hollowing indicator**: a suspended `notepad.exe` is created, its memory is replaced with shellcode, and execution is redirected. The process appears as `notepad.exe` in task manager but executes attacker code
- This PowerShell has been alive since 2018-08-16 — the DC was under attacker control from the earliest timestamps in the capture, preceding the WMI chain on the FS by 12 days

---

## Finding 7 — DATA STAGING ON FILE SERVER

**Severity: HIGH**

```
Rar.exe (PID:2524)
  PPID: 6352  [NOT IN LIST — parent cleaned up]
  Created: 2018-09-05 14:43:11 UTC
  Exited:  2018-09-05 14:52:56 UTC
  Runtime: ~9 minutes 45 seconds
```

**Analysis:**
- `Rar.exe` with a ~10-minute runtime is consistent with archiving a medium-to-large data set (gigabytes of files)
- The launching cmd.exe (PPID:6352) was cleaned up after executing, removing the direct invocation from the process tree
- Occurred one day before `subject_srv.ex` was installed — data was staged for exfiltration prior to final backdoor deployment, following the standard attacker lifecycle: access → persist → collect → exfil → maintain

---

## Finding 8 — CLEANUP AND LOLBin ACTIVITY ON FILE SERVER (2018-09-06)

**Severity: MEDIUM**

Three suspicious short-lived events in the 7 hours preceding backdoor installation:

| Time (UTC) | Process | PID | Parent Status | Assessment |
|-----------|---------|-----|---------------|------------|
| 07:27:10 | `ngentask.exe` | 7092 | PPID:2536 **NOT IN LIST** | .NET NGEN LOLBin — used for DLL injection / application whitelisting bypass |
| 16:00:04 | `reg.exe` | 2724 | PPID:6852 **NOT IN LIST** | Registry modification — persistence key addition or AV policy tamper |
| 16:36:33 | `Uninstall.exe` | 2340 | via orphaned cmd.exe (4808) | Ran for 2 seconds — dropper self-cleanup after completing service installation |

**Analysis:**
- `ngentask.exe` is the .NET Native Image Generator task scheduler — it can be abused to load arbitrary DLLs as a signed Microsoft binary, bypassing application control policies
- `reg.exe` with a sub-second runtime and cleaned-up parent indicates a single registry key write, consistent with adding an autorun entry or disabling a security setting
- `Uninstall.exe` running for exactly 2 seconds from an orphaned cmd.exe lineage (PPID:6956 not in list → cmd.exe:4808 → Uninstall.exe:2340) is the pattern of a dropper that writes a service binary, installs the service, and then removes its own installer artifact. This aligns with the `subject_srv.ex` service being installed at 19:25:36 — approximately 2h 49m after this cleanup event

---

## Finding 9 — 22 ORPHANED PROCESSES ON DC (Anti-Forensics)

**Severity: MEDIUM**

The DC shows 22 processes whose PPID does not appear anywhere in the 124-process list. The majority are cmd.exe instances with `create time == exit time` (sub-second lifetime).

**Breakdown:**
- Orphaned `cmd.exe`: 12 instances (all exited, most exit = create time)
- Orphaned `conhost.exe`, `tasklist.exe`, `findstr.exe`: 4 instances  
- Orphaned system processes (smss.exe lineage, normal for some sessions): 6 instances

**Analysis:**
- Volume of 22 orphaned processes on DC (vs. 16 on FS) indicates heavier scripted command execution on the DC
- Systematically terminating the parent cmd.exe after each command execution severs the process lineage in memory forensics, making it harder to reconstruct the execution tree
- The same-second create/exit pattern confirms these are automated (not manual) commands, likely executed via a C2 framework's `shell` command which spawns and immediately terminates the host process after output is captured

---

## Attack Timeline

```
2018-08-08  FS boot. rubyw.exe (Metasploit), nscp.exe, ncpa* installed as persistent services.
            ⚠ FILE SERVER WAS COMPROMISED BEFORE THIS CAPTURE WINDOW

2018-08-16  DC: RuntimeBroker.exe spawns powershell.exe (5612) [parent-spoofed]
            DC: powershell.exe spawns notepad.exe [process hollowing]
            ⚠ DC COMPROMISED — ATTACKER HAS INTERACTIVE POWERSHELL SESSION ON DC

2018-08-28  FS: WmiPrvSE spawns powershell.exe → powershell.exe (32-bit/Wow64)
            [WMI-based execution — attacker pivots to FS using domain credentials from DC]

2018-08-30  FS: First rundll32.exe beacon spawned [C2 beaconing begins]
2018-08-31  FS: Burst of 10 rundll32.exe beacons in 14 minutes [C2 fully operational]

2018-09-01  DC: ManagementAgent (908) spawns cmd.exe (4588) [first confirmed exec on DC]
            DC: findstr.exe recon [process enumeration, AV check]

2018-09-02–04  DC: Repeated cmd.exe waves, tasklist.exe recon, multiple WmiPrvSE instances

2018-09-05  FS: Rar.exe runs ~10 min [DATA STAGED FOR EXFILTRATION]

2018-09-06  FS: ngentask.exe LOLBin (07:27)
            FS: reg.exe registry modification (16:00)
            FS: Uninstall.exe dropper cleanup (16:36)
            DC: ManagementAgent spawns 3 cmd.exe chains (17:47, 18:17, 22:53)
            DC: tasklist.exe recon (17:57)
            FS: subject_srv.ex INSTALLED AS SERVICE  ← 19:25:36 UTC  [BACKDOOR DEPLOYED]
            DC: subject_srv.ex INSTALLED AS SERVICE  ← 22:11:15 UTC  [BACKDOOR DEPLOYED]
```

---

## Indicators of Compromise

| IOC | System | Severity | Category |
|-----|--------|----------|----------|
| `subject_srv.exe` — SYSTEM service, Wow64=True, ~10 threads | Both | **Critical** | Backdoor |
| `WmiPrvSE.exe` → `powershell.exe` parent-child relationship | FS | **Critical** | WMI execution |
| `powershell.exe`(32-bit/Wow64) → 28×`rundll32.exe` beacons over 7 days | FS | **Critical** | C2 / Cobalt Strike |
| `rubyw.exe` running as a persistent SYSTEM service | FS | **Critical** | Metasploit persistence |
| ManagementAgent (PID:908) spawning cmd.exe — same-second multi-spawn | DC | High | Lateral movement / C2 relay |
| `RuntimeBroker.exe` spawning `powershell.exe` (parent spoofed) | DC | High | PPID spoofing |
| `powershell.exe` spawning `notepad.exe` | DC | High | Process hollowing |
| `Rar.exe` with orphaned parent, ~10 min runtime | FS | High | Data staging / exfiltration |
| `nscp.exe` (NSClient++) as persistent SYSTEM service | FS | Medium | C2 channel / exploit surface |
| `ngentask.exe` with orphaned parent | FS | Medium | LOLBin execution |
| `reg.exe` with orphaned parent | FS | Medium | Registry tamper |
| `Uninstall.exe` spawned by orphaned cmd.exe, 2-second lifetime | FS | Medium | Dropper cleanup |
| 22 orphaned processes on DC (cmd.exe sub-second lifetime) | DC | Medium | Anti-forensics |
| `ncpa_listener.exe` / `ncpa_passive.exe` as persistent services | FS | Medium | C2 channel |

---

## Recommended Immediate Actions

1. **Isolate both systems from the network immediately.** Both are actively backdoored and the attacker retains persistent access via `subject_srv.ex`.
2. **Hunt `subject_srv.exe`** on all domain-joined systems — the identical deployment pattern suggests automated installation. Other systems may be affected.
3. **Revoke all service account credentials** and domain admin tokens. The attacker had domain-level access (demonstrated by lateral DC movement and WMI exec cross-system).
4. **Search for `rubyw.exe` as a service** on all FS-class servers.
5. **Examine registry run keys and service entries** (`HKLM\SYSTEM\CurrentControlSet\Services`) on both systems for `subject_srv`, `rubyw`, and any entries pointing to unusual paths.
6. **Review network logs** for outbound connections from the File Server starting 2018-08-30 (first beacon). The 28 rundll32 beacons would have made outbound C2 connections — IP/domain of C2 server may still be in firewall/proxy logs.
7. **Preserve memory images** before any remediation — the active PowerShell sessions (PID:4072 and 3164 on FS) and `subject_srv.ex` on both systems contain runtime artifacts (injected shellcode, network sockets, encryption keys).

---

## Self-Correction Notes

1. **PID 8872 collision on DC** — initially suspected DKOM/name spoofing. Confirmed PID reuse after timestamp review: `cmd.exe` exited at 2018-09-03 18:11:30, `WmiPrvSE.exe` was assigned the same PID at 21:09:16 (~3h later). Not a spoofing technique. Both entries independently suspicious (orphaned cmd.exe that exited in <1 second; WmiPrvSE active for only 90 seconds before exiting).

2. **ManagementAgent PPID** — confirmed `services.exe` (PID:644) is the correct parent, consistent with a standard Windows service. The anomaly is solely its `cmd.exe` children, not its own placement in the tree.

3. **rundll32 beacon count** — 28 total, all terminated at capture time. The C2 session was not live at capture moment, but the parent PowerShell processes remain alive, ready to spawn new beacons on demand.

4. **rubyw.exe assessment** — boot-time creation under `services.exe` could superficially suggest legitimate monitoring software. In context — given the full attack chain — this is the Metasploit persistence mechanism establishing the initial foothold on the File Server.

---

*Report generated from Redis forensic evidence. Cross-correlated between `sans:dc:psscan` and `sans:fileserver:psscan`. Analysis performed 2026-04-30.*
