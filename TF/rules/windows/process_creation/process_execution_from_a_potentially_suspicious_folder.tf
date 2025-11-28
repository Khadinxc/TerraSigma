resource "azurerm_sentinel_alert_rule_scheduled" "process_execution_from_a_potentially_suspicious_folder" {
  name                       = "process_execution_from_a_potentially_suspicious_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Execution From A Potentially Suspicious Folder"
  description                = "Detects a potentially suspicious execution from an uncommon folder."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains ":\\Perflogs\\" or FolderPath contains ":\\Users\\All Users\\" or FolderPath contains ":\\Users\\Default\\" or FolderPath contains ":\\Users\\NetworkService\\" or FolderPath contains ":\\Windows\\addins\\" or FolderPath contains ":\\Windows\\debug\\" or FolderPath contains ":\\Windows\\Fonts\\" or FolderPath contains ":\\Windows\\Help\\" or FolderPath contains ":\\Windows\\IME\\" or FolderPath contains ":\\Windows\\Media\\" or FolderPath contains ":\\Windows\\repair\\" or FolderPath contains ":\\Windows\\security\\" or FolderPath contains ":\\Windows\\System32\\Tasks\\" or FolderPath contains ":\\Windows\\Tasks\\" or FolderPath contains "$Recycle.bin" or FolderPath contains "\\config\\systemprofile\\" or FolderPath contains "\\Intel\\Logs\\" or FolderPath contains "\\RSA\\MachineKeys\\") and (not(((FolderPath endswith "\\CitrixReceiverUpdater.exe" and FolderPath startswith "C:\\Windows\\SysWOW64\\config\\systemprofile\\Citrix\\UpdaterBinaries\\") or FolderPath startswith "C:\\Users\\Public\\IBM\\ClientSolutions\\Start_Programs\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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