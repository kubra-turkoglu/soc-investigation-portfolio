# MITRE ATT&CK Mapping

## TA0007 - Discovery

### T1033

System Owner/User Discovery

Evidence:

* whoami
* whoami /priv
* whoami /groups

### T1087

Account Discovery

Evidence:

* net user
* get-localuser

### T1082

System Information Discovery

Evidence:

* systeminfo
* wmic os get caption

### T1016

System Network Configuration Discovery

Evidence:

* ipconfig
* ipconfig /all

### T1049

System Network Connections Discovery

Evidence:

* netstat -ano

### T1518

Software Discovery

Evidence:

* sc query windefend

### T1016.001

Network Configuration Discovery

Evidence:

* arp -a
* hostname

---

## TA0002 - Execution

### T1059.001

PowerShell

Evidence:

Invoke-WebRequest

powershell -c get-localuser

powershell wmic os get caption

---

## TA0005 - Defense Evasion / Security Validation

Observed:

* Defender status checks
* Firewall status checks
* EICAR validation activity

Analyst Note:

Activity was confirmed as authorized security testing.
