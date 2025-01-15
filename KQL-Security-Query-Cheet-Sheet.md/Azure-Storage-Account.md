# Azure Storage Account

```
// Authorization Error
StorageBlobLogs
| where MetricResponseType endswith "Error"
| where StatusText == "AuthorizationPermissionMismatch"
| order by TimeGenerated asc

// Reading a bunch of blobs
StorageBlobLogs
| where OperationName == "GetBlob"

//Deleting a bunch of blobs (in a short time period)
StorageBlobLogs | where OperationName == "DeleteBlob"
| where TimeGenerated > ago(24h)

//Putting a bunch of blobs (in a short time period)
StorageBlobLogs | where OperationName == "PutBlob"
| where TimeGenerated > ago(24h)

//Copying a bunch of blobs (in a short time period)
StorageBlobLogs | where OperationName == "CopyBlob"
| where TimeGenerated > ago(24h)