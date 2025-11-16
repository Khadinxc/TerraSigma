resource "azurerm_sentinel_alert_rule_scheduled" "process_explorer_driver_creation_by_non_sysinternals_binary" {
  name                       = "process_explorer_driver_creation_by_non_sysinternals_binary"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Explorer Driver Creation By Non-Sysinternals Binary"
  description                = "Detects creation of the Process Explorer drivers by processes other than Process Explorer (procexp) itself. Hack tools or malware may use the Process Explorer driver to elevate privileges, drops it to disk for a few moments, runs a service using that driver and removes it afterwards. - Some false positives may occur with legitimate renamed process explorer binaries"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\PROCEXP" and FolderPath endswith ".sys") and (not((InitiatingProcessFolderPath endswith "\\procexp.exe" or InitiatingProcessFolderPath endswith "\\procexp64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1068"]
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