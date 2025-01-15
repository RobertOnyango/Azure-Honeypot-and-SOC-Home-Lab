# Windows Security Event Log

```
// Failed Authentication (RDP, SMB)
Event
| where EventLog == 'Security'
| where EventID == 4625
| where TimeGenerated > ago(15m)

// Authentication Success (RDP, SMB)
Event
| where EventLog == 'Security'
| where EventID == 4624
| where TimeGenerated > ago(15m)

// Brute Force Attempt
Event
| where EventLog == 'Security'
| where EventID == 4625
| extend IpAddress = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription)
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by IpAddress, EventID, Activity
| where FailureCount >= 10

// Brute Force Success Windows
let FailedLogons = Event
| where EventID == 4625 and LogonType == 3
| extend IpAddress = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription)
| where TimeGenerated > ago(60m)
| summarize FailureCount = count() by IpAddress, EventID, Activity, LogonType, DestinationHostName = Computer
| where FailureCount >= 5;
let SuccessfulLogons = Event
| where EventID == 4624 and LogonType == 3
| extend IpAddress = extract(IpAddress_REGEX_PATTERN, 0, RenderedDescription)
| where TimeGenerated > ago(60m)
| summarize SuccessfulCount = count() by IpAddress, LogonType, DestinationHostName = Computer, AuthenticationSuccessTime = TimeGenerated;
SuccessfulLogons
| join kind = leftouter FailedLogons on DestinationHostName, IpAddress, LogonType
| project AuthenticationSuccessTime, IpAddress, DestinationHostName, FailureCount, SuccessfulCount