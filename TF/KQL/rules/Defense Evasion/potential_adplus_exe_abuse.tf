resource "azurerm_sentinel_alert_rule_scheduled" "potential_adplus_exe_abuse" {
  name                       = "potential_adplus_exe_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Adplus.EXE Abuse"
  description                = "Detects execution of \"AdPlus.exe\", a binary that is part of the Windows SDK that can be used as a LOLBIN in order to dump process memory and execute arbitrary commands. - Legitimate usage of Adplus for debugging purposes"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -hang " or ProcessCommandLine contains " -pn " or ProcessCommandLine contains " -pmn " or ProcessCommandLine contains " -p " or ProcessCommandLine contains " -po " or ProcessCommandLine contains " -c " or ProcessCommandLine contains " -sc ") and (FolderPath endswith "\\adplus.exe" or ProcessVersionInfoOriginalFileName =~ "Adplus.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "CredentialAccess"]
  techniques                 = ["T1003"]
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