resource "azurerm_sentinel_alert_rule_scheduled" "pua_netcat_suspicious_execution" {
  name                       = "pua_netcat_suspicious_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Netcat Suspicious Execution"
  description                = "Detects execution of Netcat. Adversaries may use a non-application layer protocol for communication between host and C2 server or among infected hosts within a network - Legitimate ncat use"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -lvp " or ProcessCommandLine contains " -lvnp" or ProcessCommandLine contains " -l -v -p " or ProcessCommandLine contains " -lv -p " or ProcessCommandLine contains " -l --proxy-type http " or ProcessCommandLine contains " -vnl --exec " or ProcessCommandLine contains " -vnl -e " or ProcessCommandLine contains " --lua-exec " or ProcessCommandLine contains " --sh-exec ") or (FolderPath endswith "\\nc.exe" or FolderPath endswith "\\ncat.exe" or FolderPath endswith "\\netcat.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1095"]
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