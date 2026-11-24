# Incident Report #002: PowerShell Process Execution Investigation

## 1. Incident Overview

| Field | Details |
|---|---|
| Incident ID | 002 |
| Title | PowerShell Process Execution Investigation |
| Date of Investigation | September 12, 2026 |
| Data Source | Windows Sysmon Operational Log |
| SIEM | Splunk Enterprise |
| Event ID | 1 — Process Creation |
| Severity | Informational / Low |
| Classification | Benign — Authorized Testing |
| Status | Closed |
| Escalation Required | No |

## 2. Objective

Investigate PowerShell process execution using Sysmon telemetry and Splunk.

The purpose of this investigation was to identify PowerShell activity, examine command-line arguments and parent-process information, and distinguish authorized administrative activity from potentially suspicious execution.

## 3. Investigation Summary

A controlled PowerShell command was executed to generate process telemetry:

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
```

This command retrieves running processes, sorts them by CPU usage, and displays the five highest results.

Sysmon Event ID 1 recorded the process creation activity. The resulting telemetry was searched and reviewed in Splunk.

The targeted PowerShell detection query returned two matching events out of 273 events.

The investigation reviewed:

- Process image and executable path
- Command-line arguments
- Parent process image
- Parent-process command line
- Process and parent-process identifiers
- Event timestamps

## 4. Detection Query

The following SPL query was used to identify PowerShell process creation events:

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time Image CommandLine ParentImage ParentCommandLine ProcessId ParentProcessId User
| sort - _time
```

### Query Purpose

- Searches Sysmon Operational events.
- Filters for Event ID 1, which records process creation.
- Identifies Windows PowerShell and PowerShell Core executables.
- Displays command-line and parent-process information.
- Sorts results by timestamp, newest first.

## 5. Findings and Analysis

### Finding 1: Authorized PowerShell Execution

The investigation identified the controlled PowerShell command:

```powershell
Get-Process | Sort-Object CPU -Descending | Select-Object -First 5
```

The command was consistent with routine process enumeration and was executed as part of authorized lab testing.

The process-creation event provided command-line and parent-process information that could be used to investigate the activity further.

**Assessment:** Benign authorized testing.

### Finding 2: Parent-Process Analysis

The returned events included parent-process information.

Reviewing the parent process provides additional context about how a process was launched. This is important because PowerShell can be started by legitimate applications as well as by suspicious scripts or processes.

**Assessment:** Parent-process information was available for investigation. No malicious activity was established by the observed evidence.

### Finding 3: Potential False Positive — Splunk PowerShell Component

A broader search for PowerShell-related process activity also identified:

```text
C:\Program Files\Splunk\bin\splunk-powershell.exe
```

The associated process information identified `splunkd.exe` as its parent.

This demonstrated that a broad search for the word "PowerShell" can return legitimate software activity.

A SOC analyst should evaluate the executable path, parent process, command line, application context, and surrounding events before classifying an alert as malicious.

**Assessment:** Consistent with legitimate Splunk activity; not classified as malicious based on the observed evidence.

## 6. Investigation Conclusion

The investigation successfully identified PowerShell process creation events through Sysmon and Splunk.

The controlled PowerShell command was consistent with normal administrative process enumeration. The broader search also demonstrated how legitimate application components can appear in PowerShell-related results.

No confirmed malicious activity was established during this investigation.

**Final Classification:** Benign — Authorized Testing  
**Severity:** Informational / Low  
**Escalation:** Not required  
**Status:** Closed

## 7. Skills Demonstrated

- Splunk Enterprise search and investigation
- Search Processing Language (SPL)
- Windows Sysmon telemetry analysis
- Event ID 1 process-creation analysis
- PowerShell command-line investigation
- Parent-process analysis
- False-positive identification
- Evidence-based incident classification
- Security investigation documentation

## 8. Lessons Learned

1. Process execution should be evaluated in context rather than based on executable names alone.
2. Command-line arguments can provide valuable insight into process behavior.
3. Parent-process information helps establish how an executable was launched.
4. Broad searches can generate false positives from legitimate applications.
5. Detection results require investigation before an alert can be classified as malicious.

## 9. Limitations

This was a controlled home-lab investigation, not a confirmed security incident.

The available evidence demonstrates process creation and command-line investigation. It does not independently establish malicious intent, compromise, or the absence of all other suspicious activity.

---

*This investigation was performed in an authorized personal cybersecurity lab for educational and portfolio purposes.*
