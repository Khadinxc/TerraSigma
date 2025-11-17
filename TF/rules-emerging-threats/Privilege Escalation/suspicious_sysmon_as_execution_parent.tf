resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_sysmon_as_execution_parent" {
  name                       = "suspicious_sysmon_as_execution_parent"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Sysmon as Execution Parent"
  description                = "Detects suspicious process executions in which Sysmon itself is the parent of a process, which could be a sign of exploitation (e.g. CVE-2022-41120)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\Sysmon.exe" or InitiatingProcessFolderPath endswith "\\Sysmon64.exe") and (not(((FolderPath contains ":\\Windows\\Sysmon.exe" or FolderPath contains ":\\Windows\\Sysmon64.exe" or FolderPath contains ":\\Windows\\System32\\conhost.exe" or FolderPath contains ":\\Windows\\System32\\WerFault.exe" or FolderPath contains ":\\Windows\\System32\\WerFaultSecure.exe" or FolderPath contains ":\\Windows\\System32\\wevtutil.exe" or FolderPath contains ":\\Windows\\SysWOW64\\wevtutil.exe") or isnull(FolderPath) or (FolderPath contains "\\AppData\\Local\\Temp\\" and (FolderPath endswith "\\Sysmon.exe" or FolderPath endswith "\\Sysmon64.exe") and FolderPath startswith "C:\\Users\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation"]
  techniques                 = ["T1068"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}