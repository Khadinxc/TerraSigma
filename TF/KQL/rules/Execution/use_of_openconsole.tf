resource "azurerm_sentinel_alert_rule_scheduled" "use_of_openconsole" {
  name                       = "use_of_openconsole"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use of OpenConsole"
  description                = "Detects usage of OpenConsole binary as a LOLBIN to launch other binaries to bypass application Whitelisting - Legitimate use by an administrator"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoOriginalFileName =~ "OpenConsole.exe" or FolderPath endswith "\\OpenConsole.exe") and (not(FolderPath startswith "C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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