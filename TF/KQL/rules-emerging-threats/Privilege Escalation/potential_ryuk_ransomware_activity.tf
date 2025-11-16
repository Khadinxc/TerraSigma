resource "azurerm_sentinel_alert_rule_scheduled" "potential_ryuk_ransomware_activity" {
  name                       = "potential_ryuk_ransomware_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Ryuk Ransomware Activity"
  description                = "Detects Ryuk ransomware activity - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "del /s /f /q c:\\" and ProcessCommandLine contains "*.bac" and ProcessCommandLine contains "*.bak" and ProcessCommandLine contains "*.bkf") or ((ProcessCommandLine contains "samss" or ProcessCommandLine contains "audioendpointbuilder" or ProcessCommandLine contains "unistoresvc_" or ProcessCommandLine contains "AcrSch2Svc") and (ProcessCommandLine contains " stop " and ProcessCommandLine contains " /y") and (FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe")) or (ProcessCommandLine contains "Microsoft\\Windows\\CurrentVersion\\Run" and ProcessCommandLine contains "C:\\users\\Public\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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