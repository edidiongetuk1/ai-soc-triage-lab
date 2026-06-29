# AI-Augmented SOC Alert Triage Pipeline

Automated security alert triage using a local LLM (Llama 3.2) with Wazuh SIEM alerts and MITRE ATT&CK mapping. Built as part of a Blue/Purple Team cybersecurity portfolio project.

---

## What This Does

SOC analysts spend roughly 5 minutes manually triaging each alert — reading it, figuring out what kind of attack it is, deciding how serious it is, and writing up what to do next. That gets exhausting fast, especially when hundreds of alerts come in daily.

This pipeline automates that first-pass triage. It reads raw Wazuh JSON alerts, maps them to the right MITRE ATT&CK technique, scores their severity, then sends them to a locally-running Llama 3.2 model that produces a structured analysis: what happened, why it matters, what to do, and how likely it is to be a false positive.

In testing across 5 alerts covering different attack types, it cut average triage time from ~300 seconds (manual) to ~45 seconds — an 85.1% reduction. The LLM runs entirely on the local machine, so there are no API costs and no alert data leaving the network.

---

## Attack Types Covered

| Alert | MITRE Technique | Severity |
|-------|----------------|----------|
| SSH brute force | T1110.001 - Password Guessing | Medium |
| Sudo privilege escalation | T1548.003 - Sudo Caching | Critical |
| Encoded PowerShell execution | T1059.001 - PowerShell | Critical |
| Meterpreter malware detection | T1204 - User Execution | High |
| Mimikatz credential dumping | T1003 - OS Credential Dumping | Critical |

---

## Tech Stack

- **Python 3.11** — core scripting
- **Ollama + Llama 3.2 3B** — local LLM, runs on CPU, no API key needed
- **Wazuh** — SIEM platform (alert source)
- **MITRE ATT&CK** — threat intelligence framework for enrichment
- **Sigma** — standardized detection rule format
- **Colorama** — terminal output formatting

---

## Project Structure

```
ai-soc-triage-lab/
├── triage.py                        # Main pipeline script
├── alerts/
│   ├── create_alerts.py             # Generates sample Wazuh alerts
│   ├── alert1.json                  # SSH brute force
│   ├── alert2.json                  # Privilege escalation
│   ├── alert3.json                  # Encoded PowerShell
│   ├── alert4.json                  # Malware detection
│   └── alert5.json                  # Mimikatz credential dump
├── rules/
│   ├── sigma_ssh_bruteforce.yml
│   ├── sigma_mimikatz.yml
│   └── sigma_encoded_powershell.yml
├── output/
│   └── triage_*.txt                 # AI-generated triage reports
└── README.md
```

---

## How to Run

```bash
# 1. Install dependencies
pip install requests ollama colorama

# 2. Pull the model (one-time download, ~2GB)
ollama pull llama3.2

# 3. Run the pipeline
python triage.py
```

The script processes every alert in the `/alerts` folder and saves a triage report for each one to `/output/`. At the end it prints a benchmark summary comparing automated vs manual triage time.

---

## How the AI Triage Works

Each alert gets sent to Llama 3.2 with a structured prompt that includes the rule description, severity level, raw log line, agent info, and pre-mapped MITRE technique. The model is told to respond in a strict format only — no free-form text — which keeps outputs consistent and reduces hallucinations.

The prompt always asks for a false positive likelihood rating. That field is the most useful one for tier-1 analysts: it forces the model to consider whether this could be legitimate activity before escalating.

---

## Sigma Detection Rules

Three custom Sigma rules are included in `/rules/`:

**sigma_ssh_bruteforce.yml** — triggers when more than 5 failed SSH password attempts come from the same source IP within a 5-minute window. Maps to T1110.001.

**sigma_mimikatz.yml** — triggers on any process named `mimikatz.exe` or any command line containing known Mimikatz subcommands like `sekurlsa::logonpasswords` or `privilege::debug`. Maps to T1003. Level: critical.

**sigma_encoded_powershell.yml** — triggers when PowerShell runs with encoded command flags (`-Enc`, `-EncodedCommand`) combined with stealth flags (`-NonI`, `-W Hidden`), filtering out known-legitimate parent processes. Maps to T1059.001.

---

## Benchmark Results

```
Alerts processed :  5
Total automated  :  224.24 seconds
Avg per alert    :  44.85 seconds
Manual estimate  :  1,500 seconds (5 min x 5 alerts)
Time saved       :  85.1% faster than manual triage
```

---

## Prompt Engineering Notes

Getting consistent output from a 3B model required a few deliberate choices:

- **Strict format enforcement** — the prompt specifies exact field labels the model must use. Any response that drifts from the format is easy to spot.
- **Context injection** — rule level, agent name, raw log, and MITRE technique are all passed explicitly so the model isn't guessing from vague descriptions.
- **Bounded scope** — the model is told to be concise and stay within the format. Smaller models tend to ramble if not constrained.
- **False positive field** — forces the model to argue both sides before concluding. Improves accuracy on ambiguous alerts.

---

## Lessons Learned

A 3B parameter model running on CPU is slower than a cloud API but surprisingly capable for structured classification tasks. The bottleneck isn't intelligence — it's throughput. For real SOC use, you'd run a quantized model on a GPU or use a dedicated inference server, but the logic and prompt structure here would transfer directly.

The MITRE mapping is done before the AI call, not by the AI. This keeps it deterministic — the model focuses on analysis, not lookup.

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Ollama](https://ollama.com/)
- [Sigma Rules Project](https://github.com/SigmaHQ/sigma)
