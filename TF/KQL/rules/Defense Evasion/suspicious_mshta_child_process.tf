resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_mshta_child_process" {
  name                       = "suspicious_mshta_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious MSHTA Child Process"
  description                = "Detects a suspicious process spawning from an \"mshta.exe\" process, which could be indicative of a malicious HTA script execution - Printer software / driver installations - HP software"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\bitsadmin.exe") or (ProcessVersionInfoOriginalFileName in~ ("Cmd.Exe", "PowerShell.EXE", "pwsh.dll", "wscript.exe", "cscript.exe", "Bash.exe", "reg.exe", "REGSVR32.EXE", "bitsadmin.exe"))) and InitiatingProcessFolderPath endswith "\\mshta.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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