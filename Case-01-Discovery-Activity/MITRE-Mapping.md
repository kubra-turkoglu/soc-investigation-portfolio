# MITRE ATT&CK Mapping

## Overview

The observed activity contained multiple discovery and execution behaviors consistent with MITRE ATT&CK techniques.

The mapping below is based on evidence observed in the Microsoft Defender XDR process timeline.

Where the available evidence was insufficient to confidently identify a specific ATT&CK technique, the technique was marked as **Potential** rather than confirmed.

---

# TA0002 - Execution

## T1059.001 - PowerShell

**Tactic:** Execution

**Status:** Confirmed

**Evidence:**

```text
powershell wmic os get caption
powershell -c get-localuser
powershell -c Invoke-WebRequest -Uri "https://secure.eicar.org/eicar.com.txt" -OutFile "$env:USERPROFILE\Downloads\eicar_test.txt"
powershell -c 'X5O!P%@AP[4\PZX54(P)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
```

**Analysis:**

PowerShell was used to execute system discovery commands, enumerate local users, download the EICAR test file, and execute a command containing the EICAR test string.

The observed PowerShell activity is consistent with **T1059.001 - PowerShell**.

---

# TA0007 - Discovery

## T1033 - System Owner/User Discovery

**Tactic:** Discovery

**Status:** Confirmed

**Evidence:**

```text
whoami
whoami /priv
whoami /groups
```

**Analysis:**

The `whoami` commands were used to identify the current user context, privileges, and group memberships.

This behavior is consistent with **T1033 - System Owner/User Discovery**.

---

## T1087 - Account Discovery

**Tactic:** Discovery

**Status:** Confirmed

**Evidence:**

```text
net user
net user master
get-localuser
```

**Analysis:**

The commands enumerated local user accounts on the endpoint.

This behavior is consistent with **T1087 - Account Discovery**.

---

## T1082 - System Information Discovery

**Tactic:** Discovery

**Status:** Confirmed

**Evidence:**

```text
systeminfo
wmic os get caption
```

**Analysis:**

The commands collected operating system and system information from the endpoint.

This behavior is consistent with **T1082 - System Information Discovery**.

---

## T1016 - System Network Configuration Discovery

**Tactic:** Discovery

**Status:** Confirmed

**Evidence:**

```text
ipconfig
ipconfig /all
hostname
arp -a
```

**Analysis:**

The commands were used to collect hostname, network configuration, and ARP information from the endpoint.

This behavior is consistent with **T1016 - System Network Configuration Discovery**.

---

## T1016.001 - Internet Connection Discovery

**Tactic:** Discovery

**Status:** Potential

**Evidence:**

```text
ipconfig /all
```

**Analysis:**

The available evidence shows network configuration discovery, but does not provide enough context to confidently determine whether the activity specifically targeted Internet connection information.

Therefore, this sub-technique is not treated as a confirmed mapping.

---

## T1049 - System Network Connections Discovery

**Tactic:** Discovery

**Status:** Confirmed

**Evidence:**

```text
netstat -ano
```

**Analysis:**

`netstat -ano` was executed to enumerate active network connections and associated process IDs.

This behavior is consistent with **T1049 - System Network Connections Discovery**.

---

## T1518 - Software Discovery

**Tactic:** Discovery

**Status:** Potential

**Evidence:**

```text
sc query windefend
```

**Analysis:**

The command queried the Windows Defender service status.

This provides information about a security product/service installed on the endpoint.

However, the evidence is limited to a specific security service rather than a broad software inventory.

Therefore, T1518 is considered a potential rather than a confirmed mapping.

---

# TA0008 - Lateral Movement

## T1021 - Remote Services

**Tactic:** Lateral Movement

**Status:** Potential / Not Confirmed

**Evidence:**

Microsoft Defender XDR marked the observed child processes with:

```text
Remote execution
```

The process tree also showed:

```text
Remote session initiator device name: ADMIN-BASTION-01
```

and a remote session initiator IP associated with the activity.

**Analysis:**

The available telemetry indicates that the commands were executed through a remote session.

However, the specific remote service or protocol was not identified in the available process tree.

No direct evidence was observed for a specific mechanism such as:

* RDP
* WinRM
* PsExec
* SMB/Admin Shares
* WMI remote execution
* Remote PowerShell

Therefore, **T1021 - Remote Services is not confirmed**.

Additional investigation would be required to identify the underlying remote execution mechanism.

---

# TA0010 - Exfiltration / TA0011 - Command and Control

## T1105 - Ingress Tool Transfer

**Tactic:** Command and Control

**Status:** Confirmed Behavior

**Evidence:**

```text
powershell -c Invoke-WebRequest -Uri "https://secure.eicar.org/eicar.com.txt" -OutFile "$env:USERPROFILE\Downloads\eicar_test.txt"
```

**Analysis:**

PowerShell retrieved a file from an external URL and saved it to the local endpoint.

This behavior is consistent with **T1105 - Ingress Tool Transfer**.

The downloaded file was the EICAR test file and the activity was subsequently confirmed as part of an authorized security testing exercise.

Therefore, the behavior matches the ATT&CK technique even though the activity was benign in this incident.

---

# TA0005 - Defense Evasion

## Security Control Discovery

**Status:** Observed

**Potential ATT&CK Mapping:**

Security control discovery behavior was observed through the following commands:

```text
sc query windefend
netsh firewall show state
```

These commands were used to determine the status of endpoint security controls.

The exact ATT&CK technique should only be mapped after confirming the intended behavior and applicable ATT&CK version.

For this investigation, the commands are documented as **security control discovery behavior** rather than forcing an unsupported technique mapping.

---

# Observed Activity Summary

| Technique                              | ID        | Status                    | Evidence                             |
| -------------------------------------- | --------- | ------------------------- | ------------------------------------ |
| PowerShell                             | T1059.001 | Confirmed                 | PowerShell commands                  |
| System Owner/User Discovery            | T1033     | Confirmed                 | whoami, whoami /priv, whoami /groups |
| Account Discovery                      | T1087     | Confirmed                 | net user, Get-LocalUser              |
| System Information Discovery           | T1082     | Confirmed                 | systeminfo, WMIC                     |
| System Network Configuration Discovery | T1016     | Confirmed                 | ipconfig, hostname, arp              |
| System Network Connections Discovery   | T1049     | Confirmed                 | netstat -ano                         |
| Software Discovery                     | T1518     | Potential                 | sc query windefend                   |
| Remote Services                        | T1021     | Potential / Not Confirmed | Remote execution telemetry           |
| Ingress Tool Transfer                  | T1105     | Confirmed Behavior        | Invoke-WebRequest                    |
| Security Control Discovery             | —         | Observed                  | sc query windefend, netsh firewall   |

---

# Analyst Assessment

The observed activity demonstrates a sequence of host and network discovery commands executed through a remote session.

The sequence included:

```text
User / Account Discovery
        ↓
Privilege Discovery
        ↓
Network Discovery
        ↓
System Information Discovery
        ↓
Security Control Discovery
        ↓
PowerShell Execution
        ↓
External File Transfer
```

This sequence could be consistent with post-access reconnaissance and hands-on-keyboard activity.

However, the activity was validated with the system administrator and confirmed to be part of an **authorized security testing exercise**.

Therefore, the ATT&CK mappings describe the **observed behaviors**, not a determination that the environment was compromised by a malicious actor.
