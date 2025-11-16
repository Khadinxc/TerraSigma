resource "azurerm_sentinel_alert_rule_scheduled" "dllhost_exe_execution_anomaly" {
  name                       = "dllhost_exe_execution_anomaly"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Dllhost.EXE Execution Anomaly"
  description                = "Detects a \"dllhost\" process spawning with no commandline arguments which is very rare to happen and could indicate process injection activity or malware mimicking similar system processes. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine in~ ("dllhost.exe", "dllhost")) and FolderPath endswith "\\dllhost.exe") and (not(isnull(ProcessCommandLine)))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion"]
  techniques                 = ["T1055"]
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