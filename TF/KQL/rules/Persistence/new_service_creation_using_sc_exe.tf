resource "azurerm_sentinel_alert_rule_scheduled" "new_service_creation_using_sc_exe" {
  name                       = "new_service_creation_using_sc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Service Creation Using Sc.EXE"
  description                = "Detects the creation of a new service using the \"sc.exe\" utility. - Legitimate administrator or user creates a service for legitimate reasons. - Software installation"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "create" and ProcessCommandLine contains "binPath") and FolderPath endswith "\\sc.exe") and (not((InitiatingProcessFolderPath endswith "\\Dropbox.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Dropbox\\Client\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Dropbox\\Client\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
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