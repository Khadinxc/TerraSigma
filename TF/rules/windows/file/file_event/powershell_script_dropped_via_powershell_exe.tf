resource "azurerm_sentinel_alert_rule_scheduled" "powershell_script_dropped_via_powershell_exe" {
  name                       = "powershell_script_dropped_via_powershell_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Script Dropped Via PowerShell.EXE"
  description                = "Detects PowerShell creating a PowerShell file (.ps1). While often times this behavior is benign, sometimes it can be a sign of a dropper script trying to achieve persistence."
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe") and FolderPath endswith ".ps1") and (not(((FolderPath contains "\\AppData\\Local\\Temp\\" and FolderPath startswith "C:\\Users\\") or FolderPath contains "__PSScriptPolicyTest_" or FolderPath startswith "C:\\Windows\\Temp\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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