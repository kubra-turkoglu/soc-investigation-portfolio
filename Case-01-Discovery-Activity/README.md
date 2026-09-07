# Case 01 - Discovery Activity Investigation

## Scenario

An EDR/XDR tool generated an alert indicating possible group and permission discovery activity on a workstation.

The alert was associated with multiple discovery commands executed shortly after an executable was launched from a user's Downloads directory.

## Objective

Investigate whether the activity represents:

* Malicious post-compromise reconnaissance
* Unauthorized user activity
* Authorized security testing

## Detection Source

Microsoft Defender XDR

## Alert Severity

Low

## Investigation Status

Closed

## Final Classification

Benign True Positive

## Key Findings

* Discovery commands were executed successfully.
* User, privilege, network, and security enumeration were observed.
* PowerShell downloaded the EICAR test file.
* Activity was validated with the system administrator.
* The activity was part of an authorized security testing exercise.

## Skills Demonstrated

* Alert triage
* Process tree analysis
* Timeline reconstruction
* MITRE ATT&CK mapping
* Incident classification
* Stakeholder validation

