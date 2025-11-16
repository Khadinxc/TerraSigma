resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_child_processes_spawned_by_conhost" {
  name                       = "potentially_suspicious_child_processes_spawned_by_conhost"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious Child Processes Spawned by ConHost"
  description                = "Detects suspicious child processes related to Windows Shell utilities spawned by `conhost.exe`, which could indicate malicious activity using trusted system components. - Legitimate administrative tasks using `conhost.exe` to spawn child processes such as `cmd.exe`, `powershell.exe`, or `regsvr32.exe`."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\wscript.exe") or (ProcessVersionInfoOriginalFileName in~ ("cmd.exe", "cscript.exe", "mshta.exe", "powershell_ise.exe", "powershell.exe", "pwsh.dll", "regsvr32.exe", "wscript.exe"))) and InitiatingProcessFolderPath endswith "\\conhost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1202", "T1218"]
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