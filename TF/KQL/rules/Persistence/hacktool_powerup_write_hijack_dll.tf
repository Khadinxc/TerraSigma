resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_powerup_write_hijack_dll" {
  name                       = "hacktool_powerup_write_hijack_dll"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Powerup Write Hijack DLL"
  description                = "Powerup tool's Write Hijack DLL exploits DLL hijacking for privilege escalation. In it's default mode, it builds a self deleting .bat file which executes malicious command. The detection rule relies on creation of the malicious bat file (debug.bat by default). - Any powershell script that creates bat files"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe") and FolderPath endswith ".bat"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1574"]
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