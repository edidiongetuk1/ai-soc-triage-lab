import json

alerts = [
    {"timestamp":"2026-06-29T10:23:11.000Z","rule":{"id":"5710","level":10,"description":"sshd: authentication failed","groups":["authentication_failed","sshd"]},"agent":{"id":"001","name":"ubuntu-server-01","ip":"192.168.1.105"},"data":{"srcip":"45.33.32.156","srcuser":"root","dstuser":"root"},"location":"/var/log/auth.log","full_log":"Failed password for root from 45.33.32.156 port 52341 ssh2"},
    {"timestamp":"2026-06-29T10:45:02.000Z","rule":{"id":"5402","level":14,"description":"Successful sudo to root executed","groups":["syslog","sudo"]},"agent":{"id":"001","name":"ubuntu-server-01","ip":"192.168.1.105"},"data":{"srcuser":"john","dstuser":"root","command":"/bin/bash"},"location":"/var/log/auth.log","full_log":"john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash"},
    {"timestamp":"2026-06-29T11:02:44.000Z","rule":{"id":"92201","level":15,"description":"PowerShell process spawned with encoded command","groups":["windows","powershell","attack"]},"agent":{"id":"002","name":"win-server-01","ip":"192.168.1.110"},"data":{"win":{"eventdata":{"commandLine":"powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdA...","parentImage":"C:\\Windows\\System32\\cmd.exe","image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}}},"location":"EventChannel","full_log":"Sysmon Event ID 1 - Process Create: powershell.exe -Enc JABjAGwAaQBlAG4AdA..."},
    {"timestamp":"2026-06-29T11:15:30.000Z","rule":{"id":"87102","level":12,"description":"Windows Defender detected malware","groups":["windows","malware"]},"agent":{"id":"002","name":"win-server-01","ip":"192.168.1.110"},"data":{"win":{"eventdata":{"threatName":"Trojan:Win32/Meterpreter","path":"C:\\Users\\john\\Downloads\\update.exe","action":"Quarantine failed"}}},"location":"EventChannel","full_log":"Threat detected: Trojan:Win32/Meterpreter in C:\\Users\\john\\Downloads\\update.exe - Quarantine failed"},
    {"timestamp":"2026-06-29T11:28:17.000Z","rule":{"id":"18107","level":13,"description":"Mimikatz credential dumping tool detected","groups":["windows","attack","credential_dumping"]},"agent":{"id":"002","name":"win-server-01","ip":"192.168.1.110"},"data":{"win":{"eventdata":{"commandLine":"mimikatz.exe privilege::debug sekurlsa::logonpasswords","parentImage":"C:\\Windows\\System32\\cmd.exe","image":"C:\\mimikatz\\mimikatz.exe"}}},"location":"EventChannel","full_log":"Process created: mimikatz.exe privilege::debug sekurlsa::logonpasswords exit"}
]

for i, a in enumerate(alerts, 1):
    with open(f"alert{i}.json", "w") as f:
        json.dump(a, f, indent=2)
    print(f"Created alert{i}.json")

print("Done!")