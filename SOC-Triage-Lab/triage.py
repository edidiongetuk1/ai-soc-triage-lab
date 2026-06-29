import json
import os
import time
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# MITRE ATT&CK mapping
MITRE_MAP = {
    "authentication_failed": {"technique": "T1110 - Brute Force", "tactic": "Credential Access"},
    "sshd": {"technique": "T1110.001 - Password Guessing", "tactic": "Credential Access"},
    "sudo": {"technique": "T1548.003 - Sudo and Sudo Caching", "tactic": "Privilege Escalation"},
    "powershell": {"technique": "T1059.001 - PowerShell", "tactic": "Execution"},
    "attack": {"technique": "T1059 - Command and Scripting Interpreter", "tactic": "Execution"},
    "malware": {"technique": "T1204 - User Execution", "tactic": "Execution"},
    "credential_dumping": {"technique": "T1003 - OS Credential Dumping", "tactic": "Credential Access"},
    "windows": {"technique": "T1078 - Valid Accounts", "tactic": "Defense Evasion"},
}

SEVERITY_MAP = {
    range(1, 7): ("LOW", Fore.GREEN),
    range(7, 11): ("MEDIUM", Fore.YELLOW),
    range(11, 13): ("HIGH", Fore.RED),
    range(13, 16): ("CRITICAL", Fore.MAGENTA),
}

def get_severity(level):
    for r, (label, color) in SEVERITY_MAP.items():
        if level in r:
            return label, color
    return "UNKNOWN", Fore.WHITE

def get_mitre(groups):
    for group in groups:
        if group in MITRE_MAP:
            return MITRE_MAP[group]
    return {"technique": "Unknown", "tactic": "Unknown"}

def load_alert(filepath):
    with open(filepath, "r") as f:
        return json.load(f)

def triage_with_ai(alert):
    import ollama
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    groups = rule.get("groups", [])
    mitre = get_mitre(groups)

    prompt = f"""You are a SOC analyst triaging a security alert. Analyze this Wazuh alert and respond in this exact format:

SUMMARY: [one sentence describing what happened]
ATTACK_TYPE: [type of attack]
MITRE_TECHNIQUE: {mitre['technique']}
MITRE_TACTIC: {mitre['tactic']}
SEVERITY_REASON: [one sentence explaining why this is dangerous or not]
RECOMMENDED_ACTION: [one specific action the SOC team should take]
FALSE_POSITIVE_LIKELIHOOD: [Low / Medium / High] - [one sentence reason]

Alert details:
- Rule: {rule.get('description', 'N/A')}
- Rule Level: {rule.get('level', 'N/A')} out of 15
- Agent: {agent.get('name', 'N/A')} ({agent.get('ip', 'N/A')})
- Log: {alert.get('full_log', 'N/A')}
- Groups: {', '.join(groups)}

Be concise and specific. No extra text outside the format above."""

    response = ollama.chat(
        model="llama3.2",
        messages=[{"role": "user", "content": prompt}]
    )
    return response["message"]["content"]

def save_output(alert, ai_response, severity_label, mitre, elapsed, output_dir):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    rule_id = alert["rule"]["id"]
    filename = os.path.join(output_dir, f"triage_{rule_id}_{timestamp}.txt")
    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("SOC ALERT TRIAGE REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Timestamp     : {alert.get('timestamp')}\n")
        f.write(f"Agent         : {alert['agent']['name']} ({alert['agent']['ip']})\n")
        f.write(f"Rule          : {alert['rule']['description']}\n")
        f.write(f"Rule Level    : {alert['rule']['level']}/15\n")
        f.write(f"Severity      : {severity_label}\n")
        f.write(f"MITRE         : {mitre['technique']} | {mitre['tactic']}\n")
        f.write(f"Triage Time   : {elapsed:.2f} seconds\n")
        f.write("-" * 60 + "\n")
        f.write("AI ANALYSIS:\n")
        f.write(ai_response + "\n")
        f.write("=" * 60 + "\n")
    return filename

def run_triage(alerts_dir, output_dir):
    alert_files = sorted([f for f in os.listdir(alerts_dir) if f.endswith(".json")])

    print(Fore.CYAN + "\n" + "=" * 60)
    print(Fore.CYAN + "   AI-AUGMENTED SOC ALERT TRIAGE PIPELINE")
    print(Fore.CYAN + "   Powered by Llama 3.2 + MITRE ATT&CK")
    print(Fore.CYAN + "=" * 60 + "\n")

    total_start = time.time()
    results = []

    for i, fname in enumerate(alert_files, 1):
        filepath = os.path.join(alerts_dir, fname)
        alert = load_alert(filepath)
        rule = alert.get("rule", {})
        groups = rule.get("groups", [])
        level = rule.get("level", 0)
        severity_label, severity_color = get_severity(level)
        mitre = get_mitre(groups)

        print(f"{Fore.WHITE}[{i}/{len(alert_files)}] Processing: {fname}")
        print(f"  Rule     : {rule.get('description')}")
        print(f"  Level    : {level}/15")
        print(severity_color + f"  Severity : {severity_label}")
        print(f"  MITRE    : {mitre['technique']}")
        print(f"  {Fore.YELLOW}Sending to AI for analysis...")

        start = time.time()
        ai_response = triage_with_ai(alert)
        elapsed = time.time() - start

        print(Fore.GREEN + f"  AI analysis complete in {elapsed:.2f}s")
        print(Fore.WHITE + "\n" + "-" * 40)
        print(ai_response)
        print("-" * 40 + "\n")

        outfile = save_output(alert, ai_response, severity_label, mitre, elapsed, output_dir)
        results.append({"file": fname, "severity": severity_label, "time": elapsed})
        print(Fore.GREEN + f"  Saved to: {outfile}\n")

    total_elapsed = time.time() - total_start
    avg_time = total_elapsed / len(results) if results else 0

    print(Fore.CYAN + "=" * 60)
    print(Fore.CYAN + "TRIAGE COMPLETE - BENCHMARK SUMMARY")
    print(Fore.CYAN + "=" * 60)
    print(f"  Alerts processed : {len(results)}")
    print(f"  Total time       : {total_elapsed:.2f} seconds")
    print(f"  Avg per alert    : {avg_time:.2f} seconds")
    print(f"  Manual estimate  : ~300 seconds (5 min per alert)")
    manual_total = 300 * len(results)
    reduction = ((manual_total - total_elapsed) / manual_total) * 100
    print(Fore.GREEN + f"  Time saved       : {reduction:.1f}% faster than manual triage")
    print(Fore.CYAN + "=" * 60 + "\n")

if __name__ == "__main__":
    base = r"C:\Users\DATASOFT\SOC-Triage-Lab"
    alerts_dir = os.path.join(base, "alerts")
    output_dir = os.path.join(base, "output")
    run_triage(alerts_dir, output_dir)