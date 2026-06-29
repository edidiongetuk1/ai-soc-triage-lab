# Detection Playbook — AI-Augmented SOC Triage Lab

**Author:** Edidiong Etuk  
**Date:** June 2026  
**Version:** 1.0  
**Classification:** Public Portfolio Document

---

## Overview

This playbook documents the detection logic, log sources, threat profiles, and false positive mitigation strategies used in this project. It is structured the way a real SOC detection engineering team would document their work — so that any analyst joining the team can understand what each rule detects, why it was written that way, and what to do when it fires.

Three attack techniques are covered, each with its own section below.

---

## Detection 1 — SSH Brute Force

### Threat Profile

SSH brute force is one of the most common attacks against internet-facing Linux servers. An attacker tries hundreds or thousands of username/password combinations against the SSH port (22/tcp), hoping to find valid credentials. Tools like Hydra, Medusa, and Patator automate this at high speed. If successful, the attacker gains shell access to the server.

This technique maps to **MITRE ATT&CK T1110.001 — Brute Force: Password Guessing** under the Credential Access tactic.

**Why it matters:** SSH brute force is almost always the first step in a server compromise. Catching it early — before a successful login — gives the SOC team time to block the source IP and investigate whether any credentials were leaked.

### Log Sources

| Source | Location | Event to look for |
|--------|----------|-------------------|
| Linux auth log | `/var/log/auth.log` | `Failed password for` |
| Wazuh rule | Rule ID 5710 | Level 10, group: authentication_failed |
| Syslog | `/var/log/syslog` | sshd process entries |

### Detection Logic

**Sigma Rule:** `sigma_ssh_bruteforce.yml`

The rule triggers when more than 5 failed SSH authentication attempts come from the same source IP within a 5-minute window. A single failed login is normal — everyone mistype passwords. Five or more in quick succession from one IP is a brute force pattern.

Key fields checked:
- `process`: must be `sshd`
- `message`: must contain `Failed password`
- Grouped by `srcip` with a count threshold of 5
- Timeframe: 5 minutes

### False Positive Mitigation

| Scenario | Likelihood | How to handle |
|----------|-----------|---------------|
| User repeatedly mistyping their own password | Medium | Check if the source IP is internal. If yes, contact the user before blocking |
| Automated backup or monitoring script using wrong credentials | Medium | Check if the source IP belongs to a known internal system. Whitelist it in the rule |
| Legitimate penetration test | Low | Confirm with the security team whether a test is scheduled. Check the change management log |

**Tuning recommendation:** Add an IP whitelist for known internal management systems and DevOps automation tools. Review the whitelist quarterly.

---

## Detection 2 — Mimikatz Credential Dumping

### Threat Profile

Mimikatz is a post-exploitation tool that extracts plaintext passwords, hashes, and Kerberos tickets directly from Windows memory (specifically the LSASS process). It is widely used by both red teams and real-world attackers after gaining initial access to a Windows machine.

This technique maps to **MITRE ATT&CK T1003 — OS Credential Dumping** under the Credential Access tactic.

**Why it matters:** If an attacker runs Mimikatz successfully, they can steal credentials for every user who has logged into that machine — including domain admins. This typically leads to full domain compromise within minutes. A Mimikatz detection is always a critical-priority alert.

### Log Sources

| Source | Location | Event to look for |
|--------|----------|-------------------|
| Sysmon Event ID 1 | Windows Event Log | Process creation with mimikatz in image path or command line |
| Wazuh rule | Rule ID 18107 | Level 13, group: credential_dumping |
| Windows Defender | Event Log | Threat detection events |

### Detection Logic

**Sigma Rule:** `sigma_mimikatz.yml`

The rule uses two detection paths combined with OR logic — either one firing is enough to trigger an alert:

**Path 1 — Process name:** Any process where the executable filename ends with `mimikatz.exe`. Catches direct execution.

**Path 2 — Command line arguments:** Any process whose command line contains known Mimikatz subcommands:
- `sekurlsa::logonpasswords` — dumps credentials from memory
- `privilege::debug` — escalates privileges to access LSASS
- `lsadump::sam` — dumps the SAM database
- `kerberos::golden` — creates golden tickets

Path 2 catches renamed copies of Mimikatz, which attackers use to bypass simple filename-based detections.

### False Positive Mitigation

| Scenario | Likelihood | How to handle |
|----------|-----------|---------------|
| Authorized red team exercise | Low-Medium | Confirm with the security team. Red team tests should be logged in the change management system before they start |
| Security researcher on an isolated lab machine | Low | Check whether the machine is network-isolated. If yes, lower priority but still investigate |

**Tuning recommendation:** There are very few legitimate reasons for Mimikatz to run in a production environment. Treat every alert as real until proven otherwise. Do not lower the severity of this rule based on tuning alone — escalate and investigate first.

---

## Detection 3 — Encoded PowerShell Execution

### Threat Profile

PowerShell supports running Base64-encoded commands via the `-EncodedCommand` (or `-Enc`) flag. This is used legitimately by some software deployment tools, but it is also heavily abused by attackers to hide malicious commands from basic log inspection. Combined with flags like `-NonInteractive`, `-NoProfile`, and `-WindowStyle Hidden`, encoded PowerShell is a strong indicator of malicious activity.

This technique maps to **MITRE ATT&CK T1059.001 — Command and Scripting Interpreter: PowerShell** under the Execution tactic, with a secondary tag of Defense Evasion due to the obfuscation aspect.

**Why it matters:** Encoded PowerShell is the delivery mechanism for a huge range of attacks — ransomware downloaders, reverse shells, lateral movement tools, and more. Catching it early in the execution chain can stop an attack before the payload fully deploys.

### Log Sources

| Source | Location | Event to look for |
|--------|----------|-------------------|
| Sysmon Event ID 1 | Windows Event Log | Process creation: powershell.exe with encoded flags |
| Wazuh rule | Rule ID 92201 | Level 15, group: powershell, attack |
| PowerShell Script Block Logging | Windows Event Log ID 4104 | Decoded script block content |

### Detection Logic

**Sigma Rule:** `sigma_encoded_powershell.yml`

The rule requires three conditions to all be true simultaneously:

**Condition 1 — Process:** The image must be `powershell.exe`

**Condition 2 — Encoded flag present:** The command line must contain `-Enc` or `-EncodedCommand`

**Condition 3 — Stealth flags present:** The command line must also contain at least one of:
- `-NonI` or `-NonInteractive` — suppresses user prompts
- `-NoP` or `-NoProfile` — skips PowerShell profile loading
- `-W Hidden` or `-WindowStyle Hidden` — hides the console window

**Filter (NOT condition):** The parent process must NOT be `svchost.exe` — this excludes Windows Update and other legitimate system processes that occasionally use encoded PowerShell internally.

All three conditions must be true AND the filter must not match. This layered approach significantly reduces false positives compared to alerting on encoded commands alone.

### False Positive Mitigation

| Scenario | Likelihood | How to handle |
|----------|-----------|---------------|
| SCCM or Intune software deployment | Medium | Check the parent process. Legitimate deployment tools have consistent, known parent processes. Whitelist them by parent image path |
| Third-party antivirus or monitoring software | Low-Medium | Check the signing certificate of the parent process. Signed software from known vendors can be whitelisted |
| Developer testing a script locally | Low | Check the user account. If it is a developer workstation and the user is known, follow up directly but close as low priority |

**Tuning recommendation:** Enable PowerShell Script Block Logging on all Windows endpoints (Event ID 4104). This logs the decoded content of encoded commands, which makes investigation much faster. Add parent process whitelisting for confirmed legitimate tools after verifying their certificate chains.

---

## Severity Scoring Reference

All detections in this project use Wazuh's built-in rule level system (1–15) mapped to four severity tiers:

| Wazuh Level | Severity | Response SLA |
|-------------|----------|--------------|
| 1–6 | Low | Review within 24 hours |
| 7–10 | Medium | Review within 4 hours |
| 11–12 | High | Review within 1 hour |
| 13–15 | Critical | Immediate response |

---

## AI Triage Integration

Each detection feeds into the AI triage pipeline (`triage.py`). When an alert fires, the pipeline:

1. Loads the alert JSON
2. Maps the rule groups to MITRE ATT&CK using a local lookup table
3. Scores the severity based on the Wazuh rule level
4. Sends the enriched alert to Llama 3.2 with a structured prompt
5. Saves the AI analysis to `/output/` as a timestamped report

The AI output includes a false positive likelihood field for every alert. This is intentional — it forces the model to consider alternative explanations before escalating, which mirrors how an experienced tier-1 analyst thinks.

---

## References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1003 — OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)
- [MITRE ATT&CK T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma)
- [Wazuh Rule Documentation](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [Sysmon Configuration Guide](https://github.com/SwiftOnSecurity/sysmon-config)

---

*Edidiong Etuk — Blue/Purple Team Cybersecurity Portfolio, 2026*
