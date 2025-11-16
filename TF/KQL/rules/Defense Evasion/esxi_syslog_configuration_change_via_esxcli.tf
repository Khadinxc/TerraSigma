resource "azurerm_sentinel_alert_rule_scheduled" "esxi_syslog_configuration_change_via_esxcli" {
  name                       = "esxi_syslog_configuration_change_via_esxcli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ESXi Syslog Configuration Change Via ESXCLI"
  description                = "Detects changes to the ESXi syslog configuration via \"esxcli\" - Legitimate administrative activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " set" and (ProcessCommandLine contains "system" and ProcessCommandLine contains "syslog" and ProcessCommandLine contains "config") and FolderPath endswith "/esxcli"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1562", "T1059"]
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