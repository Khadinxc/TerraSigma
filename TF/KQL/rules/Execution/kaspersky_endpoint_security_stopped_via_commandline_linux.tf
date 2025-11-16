resource "azurerm_sentinel_alert_rule_scheduled" "kaspersky_endpoint_security_stopped_via_commandline_linux" {
  name                       = "kaspersky_endpoint_security_stopped_via_commandline_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Kaspersky Endpoint Security Stopped Via CommandLine - Linux"
  description                = "Detects execution of the Kaspersky init.d stop script on Linux systems either directly or via systemctl. This activity may indicate a manual interruption of the antivirus service by an administrator, or it could be a sign of potential tampering or evasion attempts by malicious actors. - System administrator manually stopping Kaspersky services"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "stop" and ProcessCommandLine contains "kesl") and (FolderPath endswith "/systemctl" or FolderPath endswith "/bash" or FolderPath endswith "/sh")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1562"]
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