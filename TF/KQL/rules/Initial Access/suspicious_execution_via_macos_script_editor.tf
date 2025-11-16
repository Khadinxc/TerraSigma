resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_execution_via_macos_script_editor" {
  name                       = "suspicious_execution_via_macos_script_editor"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Execution via macOS Script Editor"
  description                = "Detects when the macOS Script Editor utility spawns an unusual child process."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "/curl" or FolderPath endswith "/bash" or FolderPath endswith "/sh" or FolderPath endswith "/zsh" or FolderPath endswith "/dash" or FolderPath endswith "/fish" or FolderPath endswith "/osascript" or FolderPath endswith "/mktemp" or FolderPath endswith "/chmod" or FolderPath endswith "/php" or FolderPath endswith "/nohup" or FolderPath endswith "/openssl" or FolderPath endswith "/plutil" or FolderPath endswith "/PlistBuddy" or FolderPath endswith "/xattr" or FolderPath endswith "/sqlite" or FolderPath endswith "/funzip" or FolderPath endswith "/popen") or (FolderPath contains "python" or FolderPath contains "perl")) and InitiatingProcessFolderPath endswith "/Script Editor"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Execution", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1566", "T1059", "T1204", "T1553"]
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