resource "azurerm_sentinel_alert_rule_scheduled" "wsl_child_process_anomaly" {
  name                       = "wsl_child_process_anomaly"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WSL Child Process Anomaly"
  description                = "Detects uncommon or suspicious child processes spawning from a WSL process. This could indicate an attempt to evade parent/child relationship detections or persistence attempts via cron using WSL"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\wsl.exe" or InitiatingProcessFolderPath endswith "\\wslhost.exe") and ((FolderPath endswith "\\calc.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\wscript.exe") or (FolderPath contains "\\AppData\\Local\\Temp\\" or FolderPath contains "C:\\Users\\Public\\" or FolderPath contains "C:\\Windows\\Temp\\" or FolderPath contains "C:\\Temp\\" or FolderPath contains "\\Downloads\\" or FolderPath contains "\\Desktop\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1218", "T1202"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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