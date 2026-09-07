# Investigation Report

## Executive Summary

Microsoft Defender XDR detected multiple Discovery and Hands-on-Keyboard behaviors on a workstation.

The activity originated from a user-executed binary named updater.exe located within the user's Downloads directory.

Subsequent process activity included account discovery, privilege enumeration, network reconnaissance, operating system discovery, and security product discovery.

Additional PowerShell activity downloaded the EICAR test file to validate endpoint protection visibility.

The activity was later confirmed by the system administrator as part of an authorized security testing exercise.

---

## Process Tree

ntoskrnl.exe
└── smss.exe
└── smss.exe
└── winlogon.exe
└── userinit.exe
└── explorer.exe
└── updater.exe
├── cmd.exe
├── whoami.exe
├── hostname.exe
├── net.exe
├── arp.exe
├── ipconfig.exe
├── powershell.exe
├── sc.exe
├── netsh.exe
├── systeminfo.exe
└── netstat.exe

---

## Key Observations

### Account Discovery

Commands observed:

whoami

whoami /priv

whoami /groups

net user

net user <redacted>

get-localuser

Purpose:

Identify user privileges, local accounts, and security group memberships.

---

### Network Discovery

Commands observed:

hostname

arp -a

ipconfig

ipconfig /all

ipconfig /displaydns

netstat -ano

Purpose:

Enumerate network configuration and discover reachable systems.

---

### System Discovery

Commands observed:

wmic os get caption

systeminfo

Purpose:

Collect operating system and host information.

---

### Security Control Discovery

Commands observed:

sc query windefend

netsh firewall show state

Purpose:

Determine Defender and Firewall status.

---

### PowerShell Activity

PowerShell executed:

Invoke-WebRequest -Uri hxxps[://]secure[.]eicar[.]org/eicar[.]com[.]txt

Purpose:

Download EICAR test file for endpoint protection validation.

---

## Analyst Assessment

The observed command sequence strongly aligns with post-access Discovery activity commonly mapped to MITRE ATT&CK Discovery tactics.

However, validation with the system administrator confirmed the activity was part of an authorized security assessment.

No evidence of malicious payload execution or persistence was identified.

---

## Final Disposition

Benign True Positive
