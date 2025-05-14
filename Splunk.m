# ============================
# 1️⃣ High-Fidelity Detection Tuning (SPL)
# ============================
# Goal: Tune PowerShell detection to reduce false positives by filtering known benign usage
# Label: Detection Engineering

# SPL Breakdown:
| index=windows EventCode=4104 OR EventCode=4688  // Searches PowerShell logs (script blocks or process creation)
| eval cmd=coalesce(ScriptBlockText, CommandLine)  // Merges two fields to get the actual executed command
| where like(cmd, "%FromBase64String%") OR like(cmd, "%iex%")  // Filters for suspicious PowerShell patterns
| search NOT (user="svc_backup" OR user="sys_update")  // Excludes known benign service accounts
| stats count by user, host, cmd  // Aggregates by user, host, and command for alerting

# Used for: Reducing alert fatigue and tuning detection logic
