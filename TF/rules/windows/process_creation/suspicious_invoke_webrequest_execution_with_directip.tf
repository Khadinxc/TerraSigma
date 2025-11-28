resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_invoke_webrequest_execution_with_directip" {
  name                       = "suspicious_invoke_webrequest_execution_with_directip"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Invoke-WebRequest Execution With DirectIP"
  description                = "Detects calls to PowerShell with Invoke-WebRequest cmdlet using direct IP access"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "curl " or ProcessCommandLine contains "Invoke-RestMethod" or ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains " irm " or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "wget ") and ((FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell_ise.EXE", "PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine contains "://1" or ProcessCommandLine contains "://2" or ProcessCommandLine contains "://3" or ProcessCommandLine contains "://4" or ProcessCommandLine contains "://5" or ProcessCommandLine contains "://6" or ProcessCommandLine contains "://7" or ProcessCommandLine contains "://8" or ProcessCommandLine contains "://9")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}