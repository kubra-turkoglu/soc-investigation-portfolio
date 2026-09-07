# MITRE ATT&CK Mapping

## Account Discovery

Technique:
T1087

Evidence:

* net user
* get-localuser

## System Owner/User Discovery

Technique:
T1033

Evidence:

* whoami
* whoami /groups
* whoami /priv

## System Information Discovery

Technique:
T1082

Evidence:

* systeminfo
* wmic os get caption

## Network Configuration Discovery

Technique:
T1016

Evidence:

* ipconfig
* ipconfig /all

## Network Service Discovery

Technique:
T1046

Evidence:

* arp -a
* netstat -ano

## Software Discovery

Technique:
T1518

Evidence:

* sc query windefend
* netsh firewall show state

