resource "azurerm_sentinel_alert_rule_scheduled" "potential_pendingfilerenameoperations_tampering" {
  name                       = "potential_pendingfilerenameoperations_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PendingFileRenameOperations Tampering"
  description                = "Detect changes to the \"PendingFileRenameOperations\" registry key from uncommon or suspicious images locations to stage currently used files for rename or deletion after reboot. - Installers and updaters may set currently in use files for rename or deletion after a reboot."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey contains "\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations" and ((InitiatingProcessFolderPath endswith "\\reg.exe" or InitiatingProcessFolderPath endswith "\\regedit.exe") or InitiatingProcessFolderPath contains "\\Users\\Public\\")
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}