# Case 01 - Hands-on-Keyboard Discovery Investigation

## Scenario

Microsoft Defender XDR generated multiple alerts indicating account discovery, privilege enumeration, network reconnaissance, and suspicious PowerShell activity originating from a user-launched executable.

The investigation focused on determining whether the activity represented a real compromise, unauthorized user behavior, or an authorized security assessment.

---

## Detection Sources

Microsoft Defender XDR

### Alerts Triggered

1. Possible attempt to discover groups and permissions
2. Suspicious PowerShell download or encoded command execution
3. Compromised account conducting hands-on-keyboard attack

---

## Investigation Objective

Determine:

* Initial execution source
* Commands executed
* MITRE ATT&CK techniques involved
* Whether activity was malicious or authorized

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

## Final Classification

Benign True Positive

---

## Root Cause

Authorized security testing conducted by the security team.

---

## Skills Demonstrated

* Microsoft Defender XDR Investigation
* Process Tree Analysis
* Timeline Analysis
* Threat Hunting
* MITRE ATT&CK Mapping
* Alert Validation
* Incident Classification
* Stakeholder Communication
