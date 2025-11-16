resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_razerinstaller_explorer_subprocess" {
  name                       = "suspicious_razerinstaller_explorer_subprocess"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious RazerInstaller Explorer Subprocess"
  description                = "Detects a explorer.exe sub process of the RazerInstaller software which can be invoked from the installer to select a different installation folder but can also be exploited to escalate privileges to LOCAL SYSTEM - User selecting a different installation folder (check for other sub processes of this explorer.exe process)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessIntegrityLevel in~ ("System", "S-1-16-16384")) and InitiatingProcessFolderPath endswith "\\RazerInstaller.exe") and (not(FolderPath startswith "C:\\Windows\\Installer\\Razer\\Installer\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1553"]
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