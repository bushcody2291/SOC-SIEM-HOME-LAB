
# Detection Library

This directory contains Splunk Search Processing Language (SPL) queries developed and tested in my Windows SOC home lab.

The queries use Windows Security and Sysmon telemetry to identify and investigate endpoint activity.

## Detection 1: Multiple Failed Authentication Attempts

**File:** `windows-failed-logon-detection.spl`

**Data Source:** Windows Security Log

**Event ID:** 4625 — Failed Logon

**Purpose:** Identify failed authentication events and summarize activity by logon type, source address, and status codes.

**Investigation Goals:**
- Identify repeated failed authentication attempts.
- Review source address and logon type.
- Examine Windows authentication status codes.
- Establish whether the activity is consistent with authorized testing or requires further investigation.

**Lab Validation:** Successfully tested using controlled failed authentication attempts. Three failed logon events were observed within approximately seven seconds.

**Classification:** Benign authorized testing.

## Detection 2: PowerShell Process Execution

**File:** `powershell-process-execution-detection.spl`

**Data Source:** Sysmon Operational Log

**Event ID:** 1 — Process Creation

**Purpose:** Identify PowerShell process creation and display command-line and parent-process information.

**Investigation Goals:**
- Identify PowerShell executable activity.
- Review command-line arguments.
- Examine parent-process relationships.
- Distinguish expected administrative activity from activity requiring further investigation.

**Lab Validation:** Successfully tested using a controlled PowerShell process enumeration command.

**Classification:** Benign authorized testing.

## Detection Development Notes

These queries are starting points for investigation, not standalone proof of malicious activity.

Results should be reviewed in context, including:
- User and host context
- Process command lines
- Parent-process relationships
- Event timestamps
- Related endpoint and authentication events

## Tools Used

- Splunk Enterprise
- Search Processing Language (SPL)
- Windows Security Event Logging
- Microsoft Sysmon
- Windows PowerShell

---

*All queries were developed and tested in an authorized personal home lab for educational and portfolio purposes.*
