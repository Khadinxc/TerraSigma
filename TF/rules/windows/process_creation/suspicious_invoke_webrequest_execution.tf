resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_invoke_webrequest_execution" {
  name                       = "suspicious_invoke_webrequest_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Invoke-WebRequest Execution"
  description                = "Detects a suspicious call to Invoke-WebRequest cmdlet where the and output is located in a suspicious location"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "curl " or ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "wget ") and (ProcessCommandLine contains " -ur" or ProcessCommandLine contains " -o") and ((FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell_ise.EXE", "PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine contains "\\AppData\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Temp\\" or ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "%AppData%" or ProcessCommandLine contains "%Public%" or ProcessCommandLine contains "%Temp%" or ProcessCommandLine contains "%tmp%" or ProcessCommandLine contains ":\\Windows\\")
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